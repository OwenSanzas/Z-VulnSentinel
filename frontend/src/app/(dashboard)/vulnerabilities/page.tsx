"use client";

import { useCallback, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { apiFetch } from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { DataTable, type Column } from "@/components/data-table";
import { SeverityBadge } from "@/components/severity-badge";
import { StatusBadge, PipelineBadge } from "@/components/status-badge";
import { TimeAgo } from "@/components/time-ago";
import { PageHeader } from "@/components/page-header";
import { StatCard } from "@/components/stat-card";
import { SkeletonCard } from "@/components/skeleton";
import { ShieldAlert, FileWarning, ShieldCheck, Wrench } from "lucide-react";

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

interface ListResponse {
  data: ClientVulnItem[];
  meta: { next_cursor: string | null; has_more: boolean; total: number | null };
  stats: VulnStats;
}

const ALL = "__all__";

export default function VulnerabilitiesPage() {
  const router = useRouter();
  const [status, setStatus] = useState<string>(ALL);
  const [severity, setSeverity] = useState<string>(ALL);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [allData, setAllData] = useState<ClientVulnItem[]>([]);
  const [page, setPage] = useState(0);

  const filters: Record<string, string | undefined> = {
    status: status !== ALL ? status : undefined,
    severity: severity !== ALL ? severity : undefined,
  };

  const { data, isLoading } = useQuery({
    queryKey: [...queryKeys.clientVulns.list(filters), cursor, page],
    refetchInterval: 30_000,
    queryFn: async () => {
      const params = new URLSearchParams();
      params.set("page_size", "20");
      if (cursor) params.set("cursor", cursor);
      if (filters.status) params.set("status", filters.status);
      if (filters.severity) params.set("severity", filters.severity);
      const res = await apiFetch<ListResponse>(`/api/v1/client-vulns/?${params}`);
      if (page === 0) {
        setAllData(res.data);
      } else {
        setAllData((prev) => [...prev, ...res.data]);
      }
      return res;
    },
  });

  const loadMore = useCallback(() => {
    if (data?.meta.next_cursor) {
      setCursor(data.meta.next_cursor);
      setPage((p) => p + 1);
    }
  }, [data]);

  const resetPagination = useCallback(() => {
    setCursor(undefined);
    setAllData([]);
    setPage(0);
  }, []);

  const columns: Column<ClientVulnItem>[] = [
    { header: "Library", accessor: (row) => row.library_name },
    { header: "Project", accessor: (row) => row.project_name },
    { header: "Summary", accessor: (row) => <span className="truncate max-w-xs block">{row.summary || "Analyzing..."}</span> },
    { header: "Sev.", accessor: (row) => <SeverityBadge severity={row.severity} /> },
    { header: "Pipeline", accessor: (row) => <PipelineBadge status={row.pipeline_status} /> },
    { header: "Status", accessor: (row) => <StatusBadge status={row.status} /> },
    { header: "Recorded", accessor: (row) => <TimeAgo date={row.recorded_at} /> },
  ];

  const statsCards = data?.stats
    ? [
        { label: "Recorded", value: data.stats.total_recorded, icon: ShieldAlert, iconColor: "text-blue-500" },
        { label: "Reported", value: data.stats.total_reported, icon: FileWarning, iconColor: "text-yellow-500" },
        { label: "Confirmed", value: data.stats.total_confirmed, icon: ShieldCheck, iconColor: "text-orange-500" },
        { label: "Fixed", value: data.stats.total_fixed, icon: Wrench, iconColor: "text-green-500" },
      ]
    : null;

  return (
    <div className="space-y-3">
      <PageHeader title="Client Vulnerabilities" />

      <div className="grid gap-3 grid-cols-4">
        {statsCards
          ? statsCards.map((card) => <StatCard key={card.label} {...card} />)
          : Array.from({ length: 4 }).map((_, i) => <SkeletonCard key={i} />)}
      </div>

      <div className="flex gap-2">
        <Select value={status} onValueChange={(v) => { setStatus(v); resetPagination(); }}>
          <SelectTrigger className="w-36 h-7 text-xs">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>All Statuses</SelectItem>
            <SelectItem value="recorded">Recorded</SelectItem>
            <SelectItem value="reported">Reported</SelectItem>
            <SelectItem value="confirmed">Confirmed</SelectItem>
            <SelectItem value="fixed">Fixed</SelectItem>
            <SelectItem value="not_affect">Not Affected</SelectItem>
          </SelectContent>
        </Select>

        <Select value={severity} onValueChange={(v) => { setSeverity(v); resetPagination(); }}>
          <SelectTrigger className="w-36 h-7 text-xs">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL}>All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <DataTable
        columns={columns}
        data={allData}
        total={data?.meta.total}
        hasMore={data?.meta.has_more ?? false}
        onLoadMore={loadMore}
        isLoading={isLoading}
        onRowClick={(row) => router.push(`/client-vuln/${row.id}`)}
        keyExtractor={(row) => row.id}
        emptyTitle="No vulnerabilities"
        emptyDescription="No vulnerabilities match the current filters."
      />
    </div>
  );
}
