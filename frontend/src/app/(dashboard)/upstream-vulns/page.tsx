"use client";

import { useRouter } from "next/navigation";
import { usePaginatedQuery } from "@/hooks/use-paginated-query";
import { queryKeys } from "@/lib/query-keys";
import { DataTable, type Column } from "@/components/data-table";
import { SeverityBadge } from "@/components/severity-badge";
import { TimeAgo } from "@/components/time-ago";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/page-header";

interface UpstreamVulnItem {
  id: string;
  library_id: string;
  library_name: string;
  event_id: string;
  commit_sha: string;
  vuln_type: string | null;
  severity: string | null;
  status: string;
  summary: string | null;
  detected_at: string;
  published_at: string | null;
  created_at: string;
}

export default function UpstreamVulnsPage() {
  const router = useRouter();

  const vulns = usePaginatedQuery<UpstreamVulnItem>({
    queryKey: queryKeys.upstreamVulns.all,
    path: "/api/v1/upstream-vulns/",
  });

  const columns: Column<UpstreamVulnItem>[] = [
    { header: "Library", accessor: (row) => row.library_name },
    { header: "Summary", accessor: (row) => <span className="truncate max-w-xs block">{row.summary || "Analyzing..."}</span> },
    { header: "Severity", accessor: (row) => <SeverityBadge severity={row.severity} /> },
    { header: "Type", accessor: (row) => row.vuln_type || "—" },
    { header: "Status", accessor: (row) => <Badge variant="outline">{row.status}</Badge> },
    { header: "Detected", accessor: (row) => <TimeAgo date={row.detected_at} /> },
  ];

  return (
    <div className="space-y-3">
      <PageHeader title="Upstream Vulnerabilities" description="Security fixes detected in monitored libraries" />
      <DataTable
        columns={columns}
        data={vulns.data}
        total={vulns.total}
        hasMore={vulns.hasMore}
        onLoadMore={vulns.loadMore}
        isLoading={vulns.isLoading}
        onRowClick={(row) => router.push(`/upstream-vuln/${row.id}`)}
        keyExtractor={(row) => row.id}
        emptyTitle="No upstream vulnerabilities"
        emptyDescription="No upstream vulnerabilities have been detected yet."
      />
    </div>
  );
}
