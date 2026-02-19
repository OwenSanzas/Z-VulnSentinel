-- =============================================================================
-- VulnSentinel — PostgreSQL Schema
-- =============================================================================
-- Three-layer data model: events → upstream_vulns → client_vulns
-- Designed for cursor-based pagination (created_at DESC, id DESC)
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS "pgcrypto";  -- gen_random_uuid()

-- ---------------------------------------------------------------------------
-- Trigger function: auto-update updated_at on row modification
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- Enum types
-- ---------------------------------------------------------------------------

CREATE TYPE event_type           AS ENUM ('commit', 'pr_merge', 'tag', 'bug_issue');
CREATE TYPE event_classification AS ENUM ('security_bugfix', 'normal_bugfix', 'refactor', 'feature', 'other');
CREATE TYPE severity_level       AS ENUM ('critical', 'high', 'medium', 'low');
CREATE TYPE upstream_vuln_status AS ENUM ('analyzing', 'published');
CREATE TYPE snapshot_status      AS ENUM ('building', 'completed');
CREATE TYPE snapshot_backend     AS ENUM ('svf', 'joern', 'introspector', 'prebuild');
CREATE TYPE snapshot_trigger     AS ENUM ('tag_push', 'manual', 'scheduled', 'on_upstream_vuln_analysis');
CREATE TYPE client_vuln_status   AS ENUM ('recorded', 'reported', 'confirmed', 'fixed', 'not_affect');
CREATE TYPE pipeline_status      AS ENUM ('pending', 'path_searching', 'poc_generating', 'verified', 'not_affect');

-- ---------------------------------------------------------------------------
-- 1. users
-- ---------------------------------------------------------------------------

CREATE TABLE users (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username       TEXT        NOT NULL UNIQUE,
    email          TEXT        NOT NULL UNIQUE,
    password_hash  TEXT        NOT NULL,
    role           TEXT        NOT NULL DEFAULT 'viewer',  -- e.g. admin / viewer
    created_at     TIMESTAMPTZ NOT NULL    DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL    DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- 2. libraries — monitored upstream libraries
-- ---------------------------------------------------------------------------

CREATE TABLE libraries (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name             TEXT        NOT NULL UNIQUE,       -- e.g. "curl/curl"
    repo_url         TEXT        NOT NULL,              -- not unique: monorepo may host multiple libraries
    platform         TEXT        NOT NULL DEFAULT 'github',  -- github / gitlab / gitee
    default_branch   TEXT        NOT NULL DEFAULT 'main',   -- branch to monitor
    latest_tag_version    TEXT,              -- latest release tag (e.g. "v8.11.0")
    latest_commit_sha     TEXT,              -- latest tracked commit hash
    monitoring_since TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_activity_at TIMESTAMPTZ,                       -- latest event timestamp
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- cursor-based pagination
CREATE INDEX idx_libraries_cursor ON libraries (created_at DESC, id DESC);

-- ---------------------------------------------------------------------------
-- 3. projects — client projects
-- ---------------------------------------------------------------------------

CREATE TABLE projects (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name             TEXT        NOT NULL,
    organization     TEXT,                               -- client organization name
    repo_url         TEXT        NOT NULL UNIQUE,
    platform         TEXT        NOT NULL DEFAULT 'github',  -- github / gitlab / gitee
    default_branch   TEXT        NOT NULL DEFAULT 'main',   -- branch to track
    contact          TEXT,                               -- notification recipient
    current_version  TEXT,                               -- tag or branch@commit
    monitoring_since TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_update_at   TIMESTAMPTZ,                        -- latest code update
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_projects_cursor ON projects (created_at DESC, id DESC);

-- ---------------------------------------------------------------------------
-- 4. project_dependencies — project × library with version constraints
-- ---------------------------------------------------------------------------

CREATE TABLE project_dependencies (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id        UUID        NOT NULL REFERENCES projects(id)  ON DELETE CASCADE,
    library_id        UUID        NOT NULL REFERENCES libraries(id) ON DELETE CASCADE,
    constraint_expr   TEXT,                               -- e.g. ">= 8.10, < 9.0"
    resolved_version  TEXT,                               -- actual version in use
    constraint_source TEXT        NOT NULL DEFAULT '',      -- file the constraint came from (conanfile.txt, CMakeLists.txt, …)
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (project_id, library_id, constraint_source)
);

CREATE INDEX idx_projdeps_project ON project_dependencies (project_id);
CREATE INDEX idx_projdeps_library ON project_dependencies (library_id);

-- ---------------------------------------------------------------------------
-- 5. snapshots — migrated from MongoDB
-- ---------------------------------------------------------------------------
-- Original MongoDB fields preserved; new columns: project_id, trigger_type,
-- is_active, storage_path.

CREATE TABLE snapshots (
    id                    UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id            UUID            REFERENCES projects(id) ON DELETE SET NULL,
    repo_url              TEXT            NOT NULL,
    repo_name             TEXT            NOT NULL,
    version               TEXT            NOT NULL,
    backend               snapshot_backend NOT NULL,
    status                snapshot_status  NOT NULL DEFAULT 'building',
    trigger_type          snapshot_trigger,
    is_active             BOOLEAN         NOT NULL DEFAULT FALSE,
    storage_path          TEXT,

    -- preserved from MongoDB
    node_count            INT             NOT NULL DEFAULT 0,
    edge_count            INT             NOT NULL DEFAULT 0,
    fuzzer_names          TEXT[]          NOT NULL DEFAULT '{}',
    analysis_duration_sec DOUBLE PRECISION NOT NULL DEFAULT 0,
    language              TEXT            NOT NULL DEFAULT '',
    size_bytes            BIGINT          NOT NULL DEFAULT 0,
    error                 TEXT,                        -- non-NULL = build failed at current status stage

    -- timestamps
    last_accessed_at      TIMESTAMPTZ,
    access_count          INT             NOT NULL DEFAULT 0,
    created_at            TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ     NOT NULL DEFAULT now(),

    UNIQUE (repo_url, version, backend)
);

CREATE INDEX idx_snapshots_project  ON snapshots (project_id);
CREATE INDEX idx_snapshots_cursor   ON snapshots (created_at DESC, id DESC);
CREATE INDEX idx_snapshots_active   ON snapshots (project_id) WHERE is_active = TRUE;
CREATE INDEX idx_snapshots_accessed ON snapshots (last_accessed_at);

-- ---------------------------------------------------------------------------
-- 6. events — captured commits / PRs / tags / issues
-- ---------------------------------------------------------------------------

CREATE TABLE events (
    id              UUID                 PRIMARY KEY DEFAULT gen_random_uuid(),
    library_id      UUID                 NOT NULL REFERENCES libraries(id) ON DELETE CASCADE,
    type            event_type           NOT NULL,
    ref             TEXT                 NOT NULL,     -- commit SHA / PR number / tag name / issue number
    source_url      TEXT,                              -- full URL to the original commit/PR/tag/issue page
    author          TEXT,
    title           TEXT                 NOT NULL,     -- commit message / PR title / tag name / issue title
    message         TEXT,                              -- full message body (if different from title)
    -- related references (cross-platform: GitHub/GitLab/Gitee all support these)
    related_issue_ref  TEXT,                              -- e.g. "#123"
    related_issue_url  TEXT,
    related_pr_ref     TEXT,                              -- e.g. "!456" (GitLab) or "#456" (GitHub)
    related_pr_url     TEXT,
    related_commit_sha TEXT,                              -- referenced commit

    classification  event_classification,                          -- NULL = not yet classified
    confidence      DOUBLE PRECISION,                          -- NULL until classified
    is_bugfix       BOOLEAN              NOT NULL DEFAULT FALSE,  -- TRUE when classification = security_bugfix
    created_at      TIMESTAMPTZ          NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ          NOT NULL DEFAULT now(),

    CONSTRAINT uq_events_library_type_ref UNIQUE (library_id, type, ref)
);

CREATE INDEX idx_events_library   ON events (library_id);
CREATE INDEX idx_events_cursor    ON events (created_at DESC, id DESC);
-- engine polling: quickly find unprocessed security bugfixes
CREATE INDEX idx_events_bugfix    ON events (created_at DESC) WHERE is_bugfix = TRUE;
-- engine polling: find events not yet classified
CREATE INDEX idx_events_unclassified ON events (created_at DESC) WHERE classification IS NULL;

-- ---------------------------------------------------------------------------
-- 7. upstream_vulns — security bugfixes with AI analysis
-- ---------------------------------------------------------------------------

CREATE TABLE upstream_vulns (
    id                UUID                 PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id          UUID                 NOT NULL REFERENCES events(id)    ON DELETE CASCADE,
    library_id        UUID                 NOT NULL REFERENCES libraries(id) ON DELETE CASCADE,
    commit_sha        TEXT                 NOT NULL,       -- triggering commit SHA
    vuln_type         TEXT,                                -- e.g. "CWE-126 Buffer Over-read"
    severity          severity_level,
    affected_versions TEXT,                                -- e.g. "< v1.3.2"
    summary           TEXT,                                -- short description for list views
    reasoning         TEXT,                                -- AI detailed analysis
    status            upstream_vuln_status NOT NULL DEFAULT 'analyzing',
    error_message     TEXT,                                -- non-NULL = error at current status stage
    upstream_poc      JSONB,                               -- { source, reproducer, collected }

    detected_at       TIMESTAMPTZ          NOT NULL DEFAULT now(),
    published_at      TIMESTAMPTZ,                         -- set when status → published
    created_at        TIMESTAMPTZ          NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ          NOT NULL DEFAULT now()
);

CREATE INDEX idx_upvulns_event    ON upstream_vulns (event_id);
CREATE INDEX idx_upvulns_library  ON upstream_vulns (library_id);
CREATE INDEX idx_upvulns_cursor   ON upstream_vulns (created_at DESC, id DESC);
CREATE INDEX idx_upvulns_status   ON upstream_vulns (status);

-- ---------------------------------------------------------------------------
-- 8. client_vulns — per-project impact assessment
-- ---------------------------------------------------------------------------

CREATE TABLE client_vulns (
    id                UUID               PRIMARY KEY DEFAULT gen_random_uuid(),
    upstream_vuln_id  UUID               NOT NULL REFERENCES upstream_vulns(id) ON DELETE CASCADE,
    project_id        UUID               NOT NULL REFERENCES projects(id)       ON DELETE CASCADE,

    -- analysis pipeline (formerly a separate table)
    pipeline_status   pipeline_status    NOT NULL DEFAULT 'pending',
    is_affected       BOOLEAN,                     -- NULL until analysis completes
    error_message     TEXT,                        -- non-NULL = error at current pipeline stage
    analysis_started_at  TIMESTAMPTZ,
    analysis_completed_at TIMESTAMPTZ,

    -- client vuln status (set when pipeline reaches terminal state)
    status            client_vuln_status,                  -- NULL while pipeline is running

    -- status timeline — system-managed
    recorded_at       TIMESTAMPTZ,                         -- set when pipeline → verified
    reported_at       TIMESTAMPTZ,
    not_affect_at     TIMESTAMPTZ,

    -- status timeline — maintainer feedback
    confirmed_at      TIMESTAMPTZ,
    confirmed_msg     TEXT,                -- maintainer's confirmation note
    fixed_at          TIMESTAMPTZ,
    fixed_msg         TEXT,                -- maintainer's fix note (e.g. "upgraded to v1.3.2")

    -- version analysis (denormalized snapshot at creation time)
    constraint_expr   TEXT,                -- version constraint from project_dependencies
    constraint_source TEXT,
    resolved_version  TEXT,
    fix_version       TEXT,                -- from upstream_vuln affected_versions
    verdict           TEXT,                -- human-readable verdict

    -- analysis results (variable structure → JSONB)
    reachable_path    JSONB,               -- { found: bool, call_chain: [{function_name, file_path, line_number}] }
    poc_results       JSONB,               -- { poc_status, poc_type, trigger_input, crash_info, reproduce_command }
    report            JSONB,               -- { reported_to, reported_at, method, content_summary }

    created_at        TIMESTAMPTZ        NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ        NOT NULL DEFAULT now(),

    UNIQUE (upstream_vuln_id, project_id)
);

CREATE INDEX idx_clientvulns_upstream ON client_vulns (upstream_vuln_id);
CREATE INDEX idx_clientvulns_project  ON client_vulns (project_id);
CREATE INDEX idx_clientvulns_cursor   ON client_vulns (created_at DESC, id DESC);
CREATE INDEX idx_clientvulns_status   ON client_vulns (status);
-- engine polling: find client_vulns that need analysis work
CREATE INDEX idx_clientvulns_pipeline ON client_vulns (pipeline_status)
    WHERE pipeline_status IN ('pending', 'path_searching', 'poc_generating');

-- ---------------------------------------------------------------------------
-- Triggers: auto-update updated_at on every UPDATE
-- ---------------------------------------------------------------------------

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_libraries_updated_at
    BEFORE UPDATE ON libraries FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_projects_updated_at
    BEFORE UPDATE ON projects FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_project_dependencies_updated_at
    BEFORE UPDATE ON project_dependencies FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_snapshots_updated_at
    BEFORE UPDATE ON snapshots FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_events_updated_at
    BEFORE UPDATE ON events FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_upstream_vulns_updated_at
    BEFORE UPDATE ON upstream_vulns FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_client_vulns_updated_at
    BEFORE UPDATE ON client_vulns FOR EACH ROW EXECUTE FUNCTION update_updated_at();
