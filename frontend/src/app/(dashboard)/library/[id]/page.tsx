"use client";

import { use } from "react";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { apiFetch } from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";
import { usePaginatedQuery } from "@/hooks/use-paginated-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DataTable, type Column } from "@/components/data-table";
import { SeverityBadge } from "@/components/severity-badge";
import { TimeAgo } from "@/components/time-ago";
import { PageHeader } from "@/components/page-header";
import { StatCard } from "@/components/stat-card";
import { SkeletonPage } from "@/components/skeleton";
import {
  ExternalLink,
  Users,
  CalendarClock,
  Activity,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  GitCommitHorizontal,
  GitPullRequest,
  Tag,
  Bug,
} from "lucide-react";

interface UsedBy {
  project_id: string;
  project_name: string | null;
  constraint_expr: string | null;
  resolved_version: string | null;
  constraint_source: string;
}

interface CollectDetail {
  commits?: string;
  prs?: string;
  tags?: string;
  issues?: string;
  ghsa?: string;
}

interface LibraryDetail {
  id: string;
  name: string;
  repo_url: string;
  platform: string;
  ecosystem: string;
  default_branch: string;
  latest_tag_version: string | null;
  latest_commit_sha: string | null;
  monitoring_since: string;
  last_scanned_at: string | null;
  collect_status: string;
  collect_error: string | null;
  collect_detail: CollectDetail | null;
  used_by: UsedBy[];
  events_tracked: number;
}

interface UpstreamVulnItem {
  id: string;
  event_id: string;
  library_id: string;
  commit_sha: string;
  vuln_type: string | null;
  severity: string | null;
  status: string;
  summary: string | null;
  detected_at: string;
  published_at: string | null;
  created_at: string;
}

interface EventItem {
  id: string;
  library_name: string;
  type: string;
  title: string;
  classification: string | null;
  is_bugfix: boolean;
  created_at: string;
}

export default function LibraryDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const router = useRouter();

  const { data: library } = useQuery({
    queryKey: queryKeys.libraries.detail(id),
    queryFn: () => apiFetch<LibraryDetail>(`/api/v1/libraries/${id}`),
    refetchInterval: 30_000,
  });

  const vulns = usePaginatedQuery<UpstreamVulnItem>({
    queryKey: queryKeys.upstreamVulns.list(undefined, id),
    path: `/api/v1/upstream-vulns/?library_id=${id}`,
    pageSize: 20,
  });

  const events = usePaginatedQuery<EventItem>({
    queryKey: queryKeys.events.list(undefined, id),
    path: `/api/v1/events/?library_id=${id}`,
    pageSize: 20,
  });

  const usedByColumns: Column<UsedBy>[] = [
    { header: "Project", accessor: (row) => row.project_name || "—" },
    { header: "Constraint", accessor: (row) => <span className="font-mono text-[11px]">{row.constraint_expr || "—"}</span> },
    { header: "Resolved", accessor: (row) => row.resolved_version || "—" },
    { header: "Source", accessor: (row) => row.constraint_source },
  ];

  const vulnColumns: Column<UpstreamVulnItem>[] = [
    { header: "Summary", accessor: (row) => <span className="truncate max-w-xs block">{row.summary || "Analyzing..."}</span> },
    { header: "Severity", accessor: (row) => <SeverityBadge severity={row.severity} /> },
    { header: "Status", accessor: (row) => <Badge variant="outline">{row.status}</Badge> },
    { header: "Detected", accessor: (row) => <TimeAgo date={row.detected_at} /> },
  ];

  const eventColumns: Column<EventItem>[] = [
    { header: "Title", accessor: (row) => <span className="truncate max-w-sm block">{row.title}</span> },
    { header: "Type", accessor: (row) => <Badge variant="outline">{row.type}</Badge> },
    {
      header: "Class",
      accessor: (row) =>
        row.is_bugfix ? (
          <Badge className="bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/25">Bugfix</Badge>
        ) : row.classification ? (
          <Badge variant="secondary">{row.classification}</Badge>
        ) : (
          <span className="text-muted-foreground">—</span>
        ),
    },
    { header: "Time", accessor: (row) => <TimeAgo date={row.created_at} /> },
  ];

  const collectors = [
    { key: "commits" as const, label: "Commits", icon: GitCommitHorizontal },
    { key: "prs" as const, label: "Pull Requests", icon: GitPullRequest },
    { key: "tags" as const, label: "Tags", icon: Tag },
    { key: "issues" as const, label: "Issues", icon: Bug },
    { key: "ghsa" as const, label: "GHSA", icon: AlertTriangle },
  ];

  if (!library) return <SkeletonPage />;

  const isUnhealthy = library.collect_status === "unhealthy";

  return (
    <div className="space-y-3">
      <PageHeader
        title={
          <span className="inline-flex items-center gap-2">
            {library.name}
            <a href={library.repo_url} target="_blank" rel="noopener noreferrer"
              className="text-muted-foreground hover:text-foreground transition-colors">
              <ExternalLink className="h-4 w-4" />
            </a>
          </span>
        }
        description={`${library.platform} · ${library.ecosystem} · ${library.default_branch}${library.latest_tag_version ? ` · v${library.latest_tag_version}` : ""}`}
        actions={
          <span className={`flex items-center gap-1.5 text-xs font-medium ${isUnhealthy ? "text-red-500" : "text-emerald-500"}`}>
            {isUnhealthy ? <XCircle className="h-3.5 w-3.5" /> : <CheckCircle2 className="h-3.5 w-3.5" />}
            {isUnhealthy ? "Unhealthy" : "Healthy"}
          </span>
        }
      />

      {isUnhealthy && library.collect_error && (
        <div className="flex items-start gap-2 rounded-md border border-red-500/25 bg-red-500/5 p-3">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5 shrink-0" />
          <div className="text-sm">
            <span className="font-medium text-red-600 dark:text-red-400">Collection Error</span>
            <p className="text-muted-foreground mt-0.5 text-xs font-mono break-all">{library.collect_error}</p>
          </div>
        </div>
      )}

      <div className="grid gap-3 grid-cols-4">
        <StatCard label="Used By" value={`${library.used_by.length} projects`} icon={Users} />
        <StatCard label="Events Tracked" value={library.events_tracked} icon={CalendarClock} />
        <StatCard label="Last Scanned" value={library.last_scanned_at ? new Date(library.last_scanned_at).toLocaleDateString() : "—"} icon={Activity} />
        <StatCard
          label="Status"
          value={isUnhealthy ? "Unhealthy" : "Healthy"}
          icon={isUnhealthy ? XCircle : CheckCircle2}
        />
      </div>

      {/* Sub-collector status */}
      <Card>
        <CardHeader>
          <CardTitle>Sources</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4 flex-wrap">
            {collectors.map(({ key, label, icon: Icon }) => {
              const status = library.collect_detail?.[key];
              const isOk = status === "ok";
              const hasStatus = status !== undefined && status !== null;

              return (
                <div
                  key={key}
                  className="flex items-center gap-2"
                  title={hasStatus && !isOk ? status : undefined}
                >
                  {hasStatus ? (
                    isOk ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                    ) : (
                      <XCircle className="h-4 w-4 text-red-500" />
                    )
                  ) : (
                    <span className="h-4 w-4 rounded-full border-2 border-muted-foreground/30 inline-block" />
                  )}
                  <div className="flex items-center gap-1.5">
                    <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                    <span className="text-sm">{label}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {library.used_by.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Used By</CardTitle>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={usedByColumns}
              data={library.used_by}
              hasMore={false}
              onLoadMore={() => {}}
              onRowClick={(row) => router.push(`/project/${row.project_id}`)}
              keyExtractor={(row) => row.project_id}
            />
          </CardContent>
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Upstream Vulnerabilities</CardTitle>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={vulnColumns}
              data={vulns.data}
              hasMore={vulns.hasMore}
              onLoadMore={vulns.loadMore}
              isLoading={vulns.isLoading}
              onRowClick={(row) => router.push(`/upstream-vuln/${row.id}`)}
              keyExtractor={(row) => row.id}
              emptyTitle="No vulnerabilities"
              emptyDescription="No upstream vulnerabilities detected."
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent Commits</CardTitle>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={eventColumns}
              data={events.data}
              hasMore={events.hasMore}
              onLoadMore={events.loadMore}
              isLoading={events.isLoading}
              onRowClick={(row) => router.push(`/event/${row.id}`)}
              keyExtractor={(row) => row.id}
              emptyTitle="No commits"
              emptyDescription="No events recorded yet."
            />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
