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
import { TimeAgo } from "@/components/time-ago";
import { PageHeader } from "@/components/page-header";
import { SkeletonPage } from "@/components/skeleton";
import { ExternalLink } from "lucide-react";
import Link from "next/link";

interface UpstreamVulnItem {
  id: string;
  summary: string | null;
  severity: string | null;
  status: string;
  detected_at: string;
}

interface EventDetail {
  id: string;
  library_id: string;
  library_name: string;
  type: string;
  ref: string;
  source_url: string | null;
  author: string | null;
  title: string;
  message: string | null;
  classification: string | null;
  confidence: number | null;
  is_bugfix: boolean;
  event_at: string | null;
  created_at: string;
  related_issue_ref: string | null;
  related_issue_url: string | null;
  related_pr_ref: string | null;
  related_pr_url: string | null;
  related_commit_sha: string | null;
  related_vulns: UpstreamVulnItem[];
}

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex justify-between items-center py-1">
      <span className="text-muted-foreground">{label}</span>
      <span>{children}</span>
    </div>
  );
}

export default function EventDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const router = useRouter();

  const { data: event } = useQuery({
    queryKey: queryKeys.events.detail(id),
    queryFn: () => apiFetch<EventDetail>(`/api/v1/events/${id}`),
    refetchInterval: 30_000,
  });

  const vulnColumns: Column<UpstreamVulnItem>[] = [
    { header: "Summary", accessor: (row) => <span className="truncate max-w-sm block">{row.summary || "Analyzing..."}</span> },
    { header: "Severity", accessor: (row) => <SeverityBadge severity={row.severity} /> },
    { header: "Status", accessor: (row) => <Badge variant="outline">{row.status}</Badge> },
    { header: "Detected", accessor: (row) => <TimeAgo date={row.detected_at} /> },
  ];

  if (!event) return <SkeletonPage />;

  return (
    <div className="space-y-3">
      <div>
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
          <Link href={`/library/${event.library_id}`} className="hover:text-foreground transition-colors">
            {event.library_name}
          </Link>
          <span>/</span>
          <Badge variant="outline">{event.type}</Badge>
        </div>
        <PageHeader title={event.title} />
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Details</CardTitle></CardHeader>
          <CardContent className="text-xs space-y-0 divide-y divide-border">
            <DetailRow label="Ref"><span className="font-mono">{event.ref}</span></DetailRow>
            {event.author && <DetailRow label="Author">{event.author}</DetailRow>}
            <DetailRow label="Classification">
              {event.is_bugfix ? (
                <Badge className="bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/25">Security Bugfix</Badge>
              ) : (
                <span>{event.classification || "Unclassified"}</span>
              )}
            </DetailRow>
            {event.confidence !== null && (
              <DetailRow label="Confidence">{(event.confidence * 100).toFixed(0)}%</DetailRow>
            )}
            {event.event_at && <DetailRow label="Event Time"><TimeAgo date={event.event_at} /></DetailRow>}
            <DetailRow label="Recorded"><TimeAgo date={event.created_at} /></DetailRow>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle>References</CardTitle></CardHeader>
          <CardContent className="text-xs space-y-0 divide-y divide-border">
            {event.source_url && (
              <DetailRow label="Source">
                <a href={event.source_url} target="_blank" rel="noopener noreferrer"
                  className="flex items-center gap-1 text-primary hover:underline">
                  View <ExternalLink className="h-3 w-3" />
                </a>
              </DetailRow>
            )}
            {event.related_commit_sha && (
              <DetailRow label="Commit"><span className="font-mono">{event.related_commit_sha.slice(0, 8)}</span></DetailRow>
            )}
            {event.related_pr_ref && (
              <DetailRow label="PR">
                {event.related_pr_url ? (
                  <a href={event.related_pr_url} target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-1 text-primary hover:underline">
                    {event.related_pr_ref} <ExternalLink className="h-3 w-3" />
                  </a>
                ) : event.related_pr_ref}
              </DetailRow>
            )}
            {event.related_issue_ref && (
              <DetailRow label="Issue">
                {event.related_issue_url ? (
                  <a href={event.related_issue_url} target="_blank" rel="noopener noreferrer"
                    className="flex items-center gap-1 text-primary hover:underline">
                    {event.related_issue_ref} <ExternalLink className="h-3 w-3" />
                  </a>
                ) : event.related_issue_ref}
              </DetailRow>
            )}
          </CardContent>
        </Card>
      </div>

      {event.message && (
        <Card>
          <CardHeader><CardTitle>Message</CardTitle></CardHeader>
          <CardContent>
            <pre className="whitespace-pre-wrap text-xs font-mono bg-[var(--color-code-bg)] text-foreground p-3 rounded border">
              {event.message}
            </pre>
          </CardContent>
        </Card>
      )}

      {event.related_vulns.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Related Vulnerabilities ({event.related_vulns.length})</CardTitle></CardHeader>
          <CardContent>
            <DataTable
              columns={vulnColumns}
              data={event.related_vulns}
              hasMore={false}
              onLoadMore={() => {}}
              onRowClick={(row) => router.push(`/upstream-vuln/${row.id}`)}
              keyExtractor={(row) => row.id}
            />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
