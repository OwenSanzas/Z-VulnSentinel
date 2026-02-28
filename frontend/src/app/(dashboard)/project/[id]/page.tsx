"use client";

import { use, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { apiFetch } from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";
import { usePaginatedQuery } from "@/hooks/use-paginated-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DataTable, type Column } from "@/components/data-table";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge, PipelineBadge } from "@/components/status-badge";
import { TimeAgo } from "@/components/time-ago";
import { PageHeader } from "@/components/page-header";
import { StatCard } from "@/components/stat-card";
import { SkeletonPage } from "@/components/skeleton";
import { ExternalLink, ShieldAlert, FileWarning, ShieldCheck, Wrench, Loader2, AlertCircle, CheckCircle2, XCircle, ChevronDown, ChevronUp } from "lucide-react";

interface ProjectDetail {
  id: string;
  name: string;
  organization: string | null;
  repo_url: string;
  platform: string;
  default_branch: string;
  contact: string | null;
  current_version: string | null;
  monitoring_since: string;
  last_update_at: string | null;
  auto_sync_deps: boolean;
  scan_status: string;
  scan_error: string | null;
  scan_detail: Record<string, string | number> | null;
  deps_count: number;
  vuln_count: number;
}

interface ClientVulnItem {
  id: string;
  library_name: string;
  project_name: string;
  summary: string | null;
  severity: string | null;
  pipeline_status: string;
  status: string | null;
  is_affected: boolean | null;
  recorded_at: string | null;
  created_at: string;
}

interface VulnStats {
  total_recorded: number;
  total_reported: number;
  total_confirmed: number;
  total_fixed: number;
}

interface DependencyItem {
  id: string;
  library_id: string;
  library_name: string;
  constraint_expr: string | null;
  resolved_version: string | null;
  constraint_source: string;
  notify_enabled: boolean;
  created_at: string;
}

const STEP_LABELS: Record<string, string> = {
  clone: "Clone repository",
  scan: "Parse manifests",
  sync: "Sync dependencies",
};

function StepIcon({ value }: { value: string | number }) {
  if (value === "ok") return <CheckCircle2 className="h-3 w-3 text-green-500" />;
  if (value === "running") return <Loader2 className="h-3 w-3 animate-spin text-blue-500" />;
  if (typeof value === "string" && value.startsWith("error:"))
    return <XCircle className="h-3 w-3 text-red-500" />;
  return null;
}

function ScanDetailSteps({ detail }: { detail: Record<string, string | number> }) {
  const steps = ["clone", "scan", "sync"].filter((k) => k in detail);
  const counts = ["manifests", "deps_found", "synced", "deleted"].filter((k) => k in detail);

  return (
    <div className="mt-2 space-y-1 border-t border-current/10 pt-2">
      {steps.map((key) => {
        const val = detail[key];
        const isError = typeof val === "string" && val.startsWith("error:");
        return (
          <div key={key} className="flex items-center gap-2">
            <StepIcon value={val} />
            <span>{STEP_LABELS[key] ?? key}</span>
            {isError && <span className="text-red-500 truncate max-w-xs">{(val as string).slice(7)}</span>}
          </div>
        );
      })}
      {counts.length > 0 && (
        <div className="flex items-center gap-3 pt-1 text-muted-foreground">
          {counts.map((key) => (
            <span key={key}>{key}: {detail[key]}</span>
          ))}
        </div>
      )}
    </div>
  );
}

export default function ProjectDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const router = useRouter();
  const [showDetail, setShowDetail] = useState(false);

  const { data: project } = useQuery({
    queryKey: queryKeys.projects.detail(id),
    queryFn: () => apiFetch<ProjectDetail>(`/api/v1/projects/${id}`),
    refetchInterval: (query) => {
      const status = query.state.data?.scan_status;
      return status === "pending" || status === "scanning" ? 3000 : false;
    },
  });

  const { data: vulnStats } = useQuery({
    queryKey: queryKeys.clientVulns.stats(id),
    queryFn: () => apiFetch<VulnStats>(`/api/v1/client-vulns/stats?project_id=${id}`),
    refetchInterval: 30_000,
  });

  const vulns = usePaginatedQuery<ClientVulnItem>({
    queryKey: queryKeys.projects.vulns(id),
    path: `/api/v1/projects/${id}/vulnerabilities`,
    pageSize: 20,
  });

  const deps = usePaginatedQuery<DependencyItem>({
    queryKey: queryKeys.projects.deps(id),
    path: `/api/v1/projects/${id}/dependencies`,
    pageSize: 20,
  });

  const vulnColumns: Column<ClientVulnItem>[] = [
    { header: "Library", accessor: (row) => row.library_name },
    { header: "Summary", accessor: (row) => <span className="truncate max-w-xs block">{row.summary || "Analyzing..."}</span> },
    { header: "Sev.", accessor: (row) => <SeverityBadge severity={row.severity} /> },
    { header: "Pipeline", accessor: (row) => <PipelineBadge status={row.pipeline_status} /> },
    { header: "Status", accessor: (row) => <StatusBadge status={row.status} /> },
    { header: "Recorded", accessor: (row) => <TimeAgo date={row.recorded_at} /> },
  ];

  const depColumns: Column<DependencyItem>[] = [
    { header: "Library", accessor: (row) => row.library_name },
    { header: "Constraint", accessor: (row) => <span className="font-mono text-[11px]">{row.constraint_expr || "—"}</span> },
    { header: "Resolved", accessor: (row) => row.resolved_version || "—" },
    { header: "Source", accessor: (row) => row.constraint_source },
    {
      header: "Notify",
      accessor: (row) =>
        row.notify_enabled ? (
          <Badge className="bg-green-500/15 text-green-600 dark:text-green-400 border-green-500/25">On</Badge>
        ) : (
          <span className="text-muted-foreground">Off</span>
        ),
    },
  ];

  if (!project) return <SkeletonPage />;

  return (
    <div className="space-y-3">
      <PageHeader
        title={project.name}
        description={[project.organization, project.contact].filter(Boolean).join(" · ") || undefined}
        actions={
          <a href={project.repo_url} target="_blank" rel="noopener noreferrer"
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors">
            Repo <ExternalLink className="h-3 w-3" />
          </a>
        }
      />

      {(project.scan_status === "pending" || project.scan_status === "scanning") && (
        <div className="rounded-md border border-blue-500/25 bg-blue-500/5 px-3 py-2 text-xs text-blue-600 dark:text-blue-400">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              Scanning dependencies...
            </div>
            {project.scan_detail && (
              <button onClick={() => setShowDetail(!showDetail)} className="flex items-center gap-0.5 hover:underline">
                Details {showDetail ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
              </button>
            )}
          </div>
          {showDetail && project.scan_detail && (
            <ScanDetailSteps detail={project.scan_detail} />
          )}
        </div>
      )}

      {project.scan_status === "error" && (
        <div className="rounded-md border border-red-500/25 bg-red-500/5 px-3 py-2 text-xs text-red-600 dark:text-red-400">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertCircle className="h-3.5 w-3.5" />
              Scan failed{project.scan_error ? `: ${project.scan_error}` : ""}
            </div>
            {project.scan_detail && (
              <button onClick={() => setShowDetail(!showDetail)} className="flex items-center gap-0.5 hover:underline">
                Details {showDetail ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
              </button>
            )}
          </div>
          {showDetail && project.scan_detail && (
            <ScanDetailSteps detail={project.scan_detail} />
          )}
        </div>
      )}

      {project.scan_status === "healthy" && project.scan_detail && (
        <div className="flex items-center gap-2 rounded-md border border-green-500/25 bg-green-500/5 px-3 py-1.5 text-xs text-green-600 dark:text-green-400">
          <CheckCircle2 className="h-3.5 w-3.5" />
          Found {project.scan_detail.deps_found ?? 0} deps from {project.scan_detail.manifests ?? 0} manifests
          {(project.scan_detail.deleted as number) > 0 && `, removed ${project.scan_detail.deleted} stale`}
        </div>
      )}

      <div className="grid gap-3 grid-cols-4">
        <StatCard label="Recorded" value={vulnStats?.total_recorded ?? 0} icon={ShieldAlert} iconColor="text-blue-500" />
        <StatCard label="Reported" value={vulnStats?.total_reported ?? 0} icon={FileWarning} iconColor="text-yellow-500" />
        <StatCard label="Confirmed" value={vulnStats?.total_confirmed ?? 0} icon={ShieldCheck} iconColor="text-orange-500" />
        <StatCard label="Fixed" value={vulnStats?.total_fixed ?? 0} icon={Wrench} iconColor="text-green-500" />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Vulnerabilities</CardTitle>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={vulnColumns}
            data={vulns.data}
            hasMore={vulns.hasMore}
            onLoadMore={vulns.loadMore}
            isLoading={vulns.isLoading}
            onRowClick={(row) => router.push(`/client-vuln/${row.id}`)}
            keyExtractor={(row) => row.id}
            emptyTitle="No vulnerabilities"
            emptyDescription="No vulnerabilities detected for this project."
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Dependencies ({project.deps_count})</CardTitle>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={depColumns}
            data={deps.data}
            hasMore={deps.hasMore}
            onLoadMore={deps.loadMore}
            isLoading={deps.isLoading}
            onRowClick={(row) => router.push(`/library/${row.library_id}`)}
            keyExtractor={(row) => row.id}
            emptyTitle="No dependencies"
            emptyDescription="No dependencies tracked for this project."
          />
        </CardContent>
      </Card>
    </div>
  );
}
