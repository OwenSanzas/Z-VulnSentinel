"use client";

import { use } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge, PipelineBadge } from "@/components/status-badge";
import { TimeAgo } from "@/components/time-ago";
import { PageHeader } from "@/components/page-header";
import { SkeletonPage } from "@/components/skeleton";
import Link from "next/link";
import { CheckCircle, Circle, Clock } from "lucide-react";

interface UpstreamVulnSummary {
  id: string;
  severity: string | null;
  summary: string | null;
  vuln_type: string | null;
  commit_sha: string;
  status: string;
}

interface ClientVulnDetail {
  id: string;
  upstream_vuln_id: string;
  project_id: string;
  library_id: string;
  library_name: string;
  project_name: string;
  summary: string | null;
  severity: string | null;
  pipeline_status: string;
  status: string | null;
  is_affected: boolean | null;
  recorded_at: string | null;
  created_at: string;
  constraint_expr: string | null;
  constraint_source: string | null;
  resolved_version: string | null;
  fix_version: string | null;
  verdict: string | null;
  reachable_path: Record<string, unknown> | null;
  poc_results: Record<string, unknown> | null;
  report: Record<string, unknown> | null;
  error_message: string | null;
  reported_at: string | null;
  confirmed_at: string | null;
  confirmed_msg: string | null;
  fixed_at: string | null;
  fixed_msg: string | null;
  upstream_vuln: UpstreamVulnSummary;
}

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex justify-between items-center py-1">
      <span className="text-muted-foreground">{label}</span>
      <span>{children}</span>
    </div>
  );
}

function TimelineStep({ label, date, msg, active }: {
  label: string; date: string | null; msg?: string | null; active: boolean;
}) {
  return (
    <div className="flex items-center gap-2 py-1">
      {date ? (
        <CheckCircle className="h-3.5 w-3.5 text-green-500 shrink-0" />
      ) : active ? (
        <Clock className="h-3.5 w-3.5 text-primary shrink-0" />
      ) : (
        <Circle className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
      )}
      <span className="text-xs font-medium flex-1">{label}</span>
      {date && <span className="text-[11px] text-muted-foreground"><TimeAgo date={date} /></span>}
      {msg && <span className="text-[11px] text-muted-foreground truncate max-w-32">{msg}</span>}
    </div>
  );
}

export default function ClientVulnDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);

  const { data: vuln } = useQuery({
    queryKey: queryKeys.clientVulns.detail(id),
    queryFn: () => apiFetch<ClientVulnDetail>(`/api/v1/client-vulns/${id}`),
    refetchInterval: 30_000,
  });

  if (!vuln) return <SkeletonPage />;

  const currentStatus = vuln.status || "pending";

  return (
    <div className="space-y-3">
      <div>
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
          <Link href={`/project/${vuln.project_id}`} className="hover:text-foreground transition-colors">
            {vuln.project_name}
          </Link>
          <span>/</span>
          <Link href={`/library/${vuln.library_id}`} className="hover:text-foreground transition-colors">
            {vuln.library_name}
          </Link>
        </div>
        <PageHeader title={vuln.summary || "Vulnerability Analysis"} />
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <Card>
          <CardHeader><CardTitle>Status</CardTitle></CardHeader>
          <CardContent className="text-xs space-y-0 divide-y divide-border">
            <DetailRow label="Severity"><SeverityBadge severity={vuln.severity} /></DetailRow>
            <DetailRow label="Pipeline"><PipelineBadge status={vuln.pipeline_status} /></DetailRow>
            <DetailRow label="Status"><StatusBadge status={vuln.status} /></DetailRow>
            <DetailRow label="Affected">
              {vuln.is_affected === null ? (
                <span className="text-muted-foreground">Pending</span>
              ) : vuln.is_affected ? (
                <Badge className="bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/25">Yes</Badge>
              ) : (
                <Badge className="bg-green-500/15 text-green-600 dark:text-green-400 border-green-500/25">No</Badge>
              )}
            </DetailRow>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Version Info</CardTitle></CardHeader>
          <CardContent className="text-xs space-y-0 divide-y divide-border">
            {vuln.resolved_version && <DetailRow label="Used">{vuln.resolved_version}</DetailRow>}
            {vuln.fix_version && <DetailRow label="Fix">{vuln.fix_version}</DetailRow>}
            {vuln.constraint_expr && <DetailRow label="Constraint"><span className="font-mono text-[11px]">{vuln.constraint_expr}</span></DetailRow>}
            {vuln.constraint_source && <DetailRow label="Source">{vuln.constraint_source}</DetailRow>}
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>Timeline</CardTitle></CardHeader>
          <CardContent className="space-y-0 divide-y divide-border">
            <TimelineStep label="Recorded" date={vuln.recorded_at} active={currentStatus === "recorded"} />
            <TimelineStep label="Reported" date={vuln.reported_at} active={currentStatus === "reported"} />
            <TimelineStep label="Confirmed" date={vuln.confirmed_at} msg={vuln.confirmed_msg} active={currentStatus === "confirmed"} />
            <TimelineStep label="Fixed" date={vuln.fixed_at} msg={vuln.fixed_msg} active={currentStatus === "fixed"} />
          </CardContent>
        </Card>
      </div>

      {vuln.verdict && (
        <Card>
          <CardHeader><CardTitle>Verdict</CardTitle></CardHeader>
          <CardContent><p className="text-xs">{vuln.verdict}</p></CardContent>
        </Card>
      )}

      {vuln.reachable_path && (
        <Card>
          <CardHeader><CardTitle>Reachable Path</CardTitle></CardHeader>
          <CardContent>
            <pre className="whitespace-pre-wrap text-[11px] font-mono bg-[var(--color-code-bg)] text-foreground p-3 rounded border overflow-auto max-h-64">
              {JSON.stringify(vuln.reachable_path, null, 2)}
            </pre>
          </CardContent>
        </Card>
      )}

      {vuln.poc_results && (
        <Card>
          <CardHeader><CardTitle>PoC Results</CardTitle></CardHeader>
          <CardContent>
            <pre className="whitespace-pre-wrap text-[11px] font-mono bg-[var(--color-code-bg)] text-foreground p-3 rounded border overflow-auto max-h-64">
              {JSON.stringify(vuln.poc_results, null, 2)}
            </pre>
          </CardContent>
        </Card>
      )}

      {vuln.error_message && (
        <Card className="border-destructive/30">
          <CardHeader><CardTitle className="text-destructive">Error</CardTitle></CardHeader>
          <CardContent><p className="text-xs text-destructive">{vuln.error_message}</p></CardContent>
        </Card>
      )}

      <Card>
        <CardHeader><CardTitle>Upstream Vulnerability</CardTitle></CardHeader>
        <CardContent className="text-xs space-y-0 divide-y divide-border">
          <DetailRow label="Summary">{vuln.upstream_vuln.summary || "—"}</DetailRow>
          <DetailRow label="Type">{vuln.upstream_vuln.vuln_type || "—"}</DetailRow>
          <DetailRow label="Commit"><span className="font-mono">{vuln.upstream_vuln.commit_sha.slice(0, 8)}</span></DetailRow>
          <div className="pt-2">
            <Link href={`/upstream-vuln/${vuln.upstream_vuln.id}`}
              className="text-xs text-primary hover:underline">
              View upstream details →
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
