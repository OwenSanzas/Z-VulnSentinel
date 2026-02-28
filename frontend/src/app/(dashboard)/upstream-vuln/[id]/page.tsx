"use client";

import { use } from "react";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { apiFetch } from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { DataTable, type Column } from "@/components/data-table";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge, PipelineBadge } from "@/components/status-badge";
import { TimeAgo } from "@/components/time-ago";
import { PageHeader } from "@/components/page-header";
import { SkeletonPage } from "@/components/skeleton";
import Link from "next/link";

interface ClientImpactItem {
  id: string;
  project_id: string;
  project_name: string;
  version_used: string | null;
  status: string | null;
  pipeline_status: string;
  is_affected: boolean | null;
}

interface UpstreamVulnDetail {
  id: string;
  event_id: string;
  library_id: string;
  library_name: string;
  commit_sha: string;
  vuln_type: string | null;
  severity: string | null;
  status: string;
  summary: string | null;
  affected_versions: string | null;
  reasoning: string | null;
  error_message: string | null;
  upstream_poc: Record<string, unknown> | null;
  affected_functions: string[];
  detected_at: string;
  published_at: string | null;
  created_at: string;
  client_impact: ClientImpactItem[];
}

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex justify-between items-center py-1">
      <span className="text-muted-foreground">{label}</span>
      <span>{children}</span>
    </div>
  );
}

export default function UpstreamVulnDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const router = useRouter();

  const { data: vuln } = useQuery({
    queryKey: queryKeys.upstreamVulns.detail(id),
    queryFn: () => apiFetch<UpstreamVulnDetail>(`/api/v1/upstream-vulns/${id}`),
    refetchInterval: 30_000,
  });

  const impactColumns: Column<ClientImpactItem>[] = [
    { header: "Project", accessor: (row) => row.project_name },
    { header: "Version", accessor: (row) => row.version_used || "—" },
    { header: "Pipeline", accessor: (row) => <PipelineBadge status={row.pipeline_status} /> },
    { header: "Status", accessor: (row) => <StatusBadge status={row.status} /> },
    {
      header: "Affected",
      accessor: (row) =>
        row.is_affected === null ? (
          <span className="text-muted-foreground">Pending</span>
        ) : row.is_affected ? (
          <Badge className="bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/25">Yes</Badge>
        ) : (
          <Badge className="bg-green-500/15 text-green-600 dark:text-green-400 border-green-500/25">No</Badge>
        ),
    },
  ];

  if (!vuln) return <SkeletonPage />;

  return (
    <div className="space-y-3">
      <div>
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
          <Link href={`/library/${vuln.library_id}`} className="hover:text-foreground transition-colors">
            {vuln.library_name}
          </Link>
          <span>/</span>
          <span>Upstream Vulnerability</span>
        </div>
        <PageHeader title={vuln.summary || "Vulnerability Analysis"} />
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Details</CardTitle></CardHeader>
          <CardContent className="text-xs space-y-0 divide-y divide-border">
            <DetailRow label="Severity"><SeverityBadge severity={vuln.severity} /></DetailRow>
            <DetailRow label="Type">{vuln.vuln_type || "—"}</DetailRow>
            <DetailRow label="Status"><Badge variant="outline">{vuln.status}</Badge></DetailRow>
            <DetailRow label="Commit"><span className="font-mono">{vuln.commit_sha.slice(0, 8)}</span></DetailRow>
            {vuln.affected_versions && <DetailRow label="Affected Versions">{vuln.affected_versions}</DetailRow>}
            <DetailRow label="Detected"><TimeAgo date={vuln.detected_at} /></DetailRow>
            {vuln.published_at && <DetailRow label="Published"><TimeAgo date={vuln.published_at} /></DetailRow>}
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Affected Functions ({vuln.affected_functions.length})</CardTitle></CardHeader>
          <CardContent>
            {vuln.affected_functions.length > 0 ? (
              <div className="space-y-1">
                {vuln.affected_functions.map((fn, i) => (
                  <div key={i} className="font-mono text-[11px] bg-[var(--color-code-bg)] text-primary px-2 py-1 rounded border">
                    {typeof fn === "string" ? fn : JSON.stringify(fn)}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">None identified</p>
            )}
          </CardContent>
        </Card>
      </div>

      {vuln.reasoning && (
        <Card>
          <CardHeader><CardTitle>Analysis</CardTitle></CardHeader>
          <CardContent>
            <pre className="whitespace-pre-wrap text-xs font-mono bg-[var(--color-code-bg)] text-foreground p-3 rounded border">
              {vuln.reasoning}
            </pre>
          </CardContent>
        </Card>
      )}

      {vuln.error_message && (
        <Card className="border-destructive/30">
          <CardHeader><CardTitle className="text-destructive">Error</CardTitle></CardHeader>
          <CardContent>
            <p className="text-xs text-destructive">{vuln.error_message}</p>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader><CardTitle>Client Impact ({vuln.client_impact.length})</CardTitle></CardHeader>
        <CardContent>
          <DataTable
            columns={impactColumns}
            data={vuln.client_impact}
            hasMore={false}
            onLoadMore={() => {}}
            onRowClick={(row) => router.push(`/client-vuln/${row.id}`)}
            keyExtractor={(row) => row.id}
            emptyTitle="No client impact"
            emptyDescription="No client projects affected."
          />
        </CardContent>
      </Card>
    </div>
  );
}
