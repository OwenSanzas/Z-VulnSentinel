# Database — PostgreSQL

> Schema definition: [`schema.sql`](schema.sql)

## ER Diagram

```
┌──────────────┐         ┌──────────────────────┐         ┌──────────────┐
│    users     │         │      libraries       │         │   projects   │
├──────────────┤         ├──────────────────────┤         ├──────────────┤
│ id       PK  │         │ id              PK   │         │ id       PK  │
│ username     │         │ name                 │         │ name         │
│ email        │         │ repo_url             │         │ organization │
│ password_hash│         │ platform             │         │ repo_url     │
│ role         │         │ default_branch       │         │ platform     │
│ created_at   │         │ latest_tag_version   │         │ default_br.  │
│ updated_at   │         │ latest_commit_sha    │         │ contact      │
└──────────────┘         │ monitoring_since     │         │ current_ver  │
                         │ last_activity_at     │         │ monitoring_  │
                         │ created_at           │         │   since      │
                         │ updated_at           │         │ last_update  │
                         └──────┬───────────────┘         │   _at        │
                                │                         │ created_at   │
                      ┌─────── │ ───────────────┐         │ updated_at   │
                      │        │                │         └──────┬───────┘
                      │        │                │                │
                ┌─────▼──────┐ │         ┌──────▼────────────────▼──────┐
                │   events   │ │         │    project_dependencies     │
                ├────────────┤ │         ├─────────────────────────────┤
                │ id      PK │ │         │ id                     PK  │
                │ library_id │ │         │ project_id        FK → proj│
                │   FK → lib │ │         │ library_id        FK → lib │
                │ type       │ │         │ constraint_expr            │
                │ ref        │ │         │ resolved_version           │
                │ source_url │ │         │ constraint_source          │
                │ author     │ │         │ UNIQUE(proj, lib, source)  │
                │ title      │ │         └─────────────────────────────┘
                │ related_*  │ │
                │ classific. │ │         ┌─────────────────────────────┐
                │ confidence │ │         │        snapshots            │
                │ is_bugfix  │ │         ├─────────────────────────────┤
                │ UNIQUE(lib,│ │         │ id                     PK  │
                │  type, ref)│ │         │ project_id        FK → proj│
                └─────┬──────┘ │         │ repo_url, repo_name        │
                      │        │         │ version                    │
                      │        │         │ backend                    │
                ┌─────▼────────▼──┐      │ status                     │
                │ upstream_vulns  │      │ trigger_type               │
                ├─────────────────┤      │ is_active                  │
                │ id          PK  │      │ storage_path               │
                │ event_id FK→evt │      │ node/edge_count            │
                │ library_id     │      │ fuzzer_names TEXT[]         │
                │   FK → lib     │      │ error                      │
                │ commit_sha     │      │ UNIQUE(url, ver, backend)  │
                │ vuln_type      │      └─────────────────────────────┘
                │ severity       │
                │ affected_vers  │
                │ summary        │
                │ reasoning      │
                │ status         │
                │ error_message  │
                │ upstream_poc   │
                │   (JSONB)      │
                │ detected_at    │
                │ published_at   │
                └───────┬────────┘
                        │
                ┌───────▼─────────┐
                │  client_vulns   │
                ├─────────────────┤
                │ id          PK  │
                │ upstream_vuln_id│
                │   FK → upvuln  │
                │ project_id     │
                │   FK → proj    │
                │                 │
                │ — pipeline —    │
                │ pipeline_status │
                │ is_affected     │
                │ error_message   │
                │ analysis_start  │
                │ analysis_end    │
                │                 │
                │ — system —      │
                │ status (nullable│
                │   until done)   │
                │ recorded_at     │
                │ reported_at     │
                │ not_affect_at   │
                │                 │
                │ — maintainer —  │
                │ confirmed_at    │
                │ confirmed_msg   │
                │ fixed_at        │
                │ fixed_msg       │
                │                 │
                │ — version —     │
                │ constraint_expr │
                │ resolved_ver    │
                │ fix_version     │
                │ verdict         │
                │                 │
                │ — results —     │
                │ reachable_path  │
                │   (JSONB)       │
                │ poc_results     │
                │   (JSONB)       │
                │ report (JSONB)  │
                │                 │
                │ UNIQUE(upvuln,  │
                │   project)      │
                └─────────────────┘
```

## Table Summary

| # | Table | Description | Key Relationships |
|---|-------|-------------|-------------------|
| 1 | `users` | JWT authentication (username, email, role) | Standalone |
| 2 | `libraries` | Monitored upstream libraries | Parent of events, upstream_vulns, project_dependencies |
| 3 | `projects` | Client projects | Parent of project_dependencies, client_vulns, snapshots |
| 4 | `project_dependencies` | Project × library version constraints | Many-to-many: projects ↔ libraries |
| 5 | `snapshots` | Code snapshots (migrated from MongoDB) | Belongs to project |
| 6 | `events` | Captured commits, PRs, tags, issues | Belongs to library |
| 7 | `upstream_vulns` | Security bugfixes with AI analysis | Belongs to event + library |
| 8 | `client_vulns` | Per-project impact (pipeline + vuln lifecycle) | Belongs to upstream_vuln + project |

### Cardinalities

```
libraries      1 ──── * events
libraries      1 ──── * upstream_vulns
libraries      1 ──── * project_dependencies
projects       1 ──── * project_dependencies
projects       1 ──── * client_vulns
projects       1 ──── * snapshots
events         1 ──── * upstream_vulns (typically 1:1, rarely 1:N)
upstream_vulns 1 ──── * client_vulns   (one per potentially affected project)
```

## Three-Layer Data Model

```
Layer 1: events              Raw monitoring data (commits, PRs, tags, issues)
           │                 AI classifies each as security_bugfix or not
           │
           ▼
Layer 2: upstream_vulns      Created when is_bugfix = true
           │                 AI analyzes vuln type, severity, affected versions
           │
           ▼
Layer 3: client_vulns        One per potentially affected project
                             Pipeline: pending → path_searching → poc_generating → verified/not_affect
                             Vuln status: recorded → reported → confirmed → fixed
```

## Error Handling Convention

All tables use the same pattern — no `error` / `failed` enum values. Instead:

| Table | Status field | Error field | Meaning |
|-------|-------------|-------------|---------|
| `snapshots` | `status` (building/completed) | `error` | non-NULL = build failed at current stage |
| `upstream_vulns` | `status` (analyzing/published) | `error_message` | non-NULL = error at current stage |
| `client_vulns` | `pipeline_status` (pending/…/verified/not_affect) | `error_message` | non-NULL = error at current pipeline stage |

This preserves which stage failed, rather than losing that information to a generic "error" state.

## Storage Architecture

VulnSentinel uses three storage systems, each for its strength:

| System | Purpose | Data |
|--------|---------|------|
| **PostgreSQL** (AWS RDS) | Business data, relational queries, pagination | All 8 tables — users, libraries, projects, dependencies, snapshots, events, vulns |
| **Neo4j** | Graph traversal for call-chain reachability | Function nodes, call edges, fuzzer targets — per snapshot |
| **Disk** (EBS / local) | Large binary artifacts | Source code snapshots, bitcode files, build artifacts; path stored in `snapshots.storage_path` |

### Query patterns by storage

- **PostgreSQL**: list/filter/paginate libraries, events, vulns; status tracking; forward-inclusion counts; cursor-based pagination via `(created_at DESC, id DESC)` indexes.
- **Neo4j**: "find a call path from project entry point to vulnerable function" — graph BFS/DFS on per-snapshot subgraphs.
- **Disk**: read source files for diff display; load bitcode for static analysis; store PoC artifacts.

## MongoDB Migration Notes

### What migrates

The `snapshots` collection moves from MongoDB (`z_code_analyzer.snapshots`) to PostgreSQL:

| MongoDB field | PostgreSQL column | Notes |
|---------------|-------------------|-------|
| `_id` (ObjectId) | `id` (UUID) | New UUIDs generated on migration |
| `repo_url` | `repo_url` | Unchanged |
| `repo_name` | `repo_name` | Unchanged |
| `version` | `version` | Unchanged |
| `backend` | `backend` | Cast to `snapshot_backend` enum |
| `status` | `status` | Cast to `snapshot_status` enum (`failed` → `building` + `error` field) |
| `created_at` | `created_at` | Unchanged |
| `last_accessed_at` | `last_accessed_at` | Unchanged |
| `access_count` | `access_count` | Unchanged |
| `node_count` | `node_count` | Unchanged |
| `edge_count` | `edge_count` | Unchanged |
| `fuzzer_names` | `fuzzer_names` | Array → `TEXT[]` |
| `analysis_duration_sec` | `analysis_duration_sec` | Unchanged |
| `language` | `language` | Unchanged |
| `size_bytes` | `size_bytes` | Unchanged |
| `error` | `error` | Unchanged |
| *(not in MongoDB)* | `project_id` | Backfill by matching `repo_url` to projects |
| *(not in MongoDB)* | `trigger_type` | Default to `NULL` for historical snapshots |
| *(not in MongoDB)* | `is_active` | Set latest completed snapshot per project to `TRUE` |
| *(not in MongoDB)* | `storage_path` | Derive from existing disk layout conventions |

### Unique constraint

MongoDB index `(repo_url, version, backend) UNIQUE` is preserved as a PostgreSQL unique constraint.

### What stays in MongoDB

Nothing. After migration, MongoDB is decommissioned. The `SnapshotManager` class will be refactored to use SQLAlchemy/asyncpg against PostgreSQL.

### Neo4j

Neo4j retains its role for graph data (function call graphs per snapshot). No changes to Neo4j schema. The `snapshot_id` stored in Neo4j node properties will reference the new PostgreSQL UUID after migration.
