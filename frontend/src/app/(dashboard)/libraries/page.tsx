"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { usePagedQuery } from "@/hooks/use-paged-query";
import { queryKeys } from "@/lib/query-keys";
import { apiFetch } from "@/lib/api";
import { PagedTable } from "@/components/paged-table";
import type { SortableColumn } from "@/components/paged-table";
import { TimeAgo } from "@/components/time-ago";
import { PageHeader } from "@/components/page-header";
import { DonutChart } from "@/components/donut-chart";
import { AlertTriangle, X } from "lucide-react";

interface LibraryItem {
  id: string;
  name: string;
  platform: string;
  ecosystem: string;
  last_scanned_at: string | null;
  collect_status: string;
  used_by_count: number;
  created_at: string;
}

interface EcoHealth {
  healthy: number;
  unhealthy: number;
}

interface HealthSummary {
  platforms: Record<string, EcoHealth>;
  unhealthy_with_clients: number;
  unhealthy_no_clients: number;
}

const ECOSYSTEM_LABELS: Record<string, string> = {
  c_cpp: "C / C++",
  rust: "Rust",
  python: "Python",
  java: "Java",
  go: "Go",
  solidity: "Solidity",
};

function StatusDot({ status }: { status: string }) {
  const isHealthy = status === "healthy";
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className={`inline-block h-2 w-2 rounded-full ${
          isHealthy ? "bg-emerald-500" : "bg-red-500"
        }`}
      />
      <span className={isHealthy ? "text-muted-foreground" : "text-red-600 dark:text-red-400"}>
        {status}
      </span>
    </span>
  );
}

export default function LibrariesPage() {
  const router = useRouter();
  const [sortBy, setSortBy] = useState("name");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [statusFilter, setStatusFilter] = useState<string | null>(null);
  const [ecoFilter, setEcoFilter] = useState<string | null>(null);

  const params = useMemo(() => {
    const p: Record<string, string> = { sort_by: sortBy, sort_dir: sortDir };
    if (statusFilter) p.status = statusFilter;
    if (ecoFilter) p.ecosystem = ecoFilter;
    return p;
  }, [sortBy, sortDir, statusFilter, ecoFilter]);

  const libraries = usePagedQuery<LibraryItem>({
    queryKey: queryKeys.libraries.all,
    path: "/api/v1/libraries/",
    params,
  });

  const healthQuery = useQuery({
    queryKey: ["libraries", "health-summary"],
    queryFn: () => apiFetch<HealthSummary>("/api/v1/libraries/health-summary"),
    refetchInterval: 30_000,
  });

  const health = healthQuery.data;

  const handleSort = (key: string) => {
    if (sortBy === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(key);
      setSortDir("asc");
    }
  };

  const handleEcoClick = (eco: string) => {
    setEcoFilter((prev) => (prev === eco ? null : eco));
  };

  const hasActiveFilter = statusFilter || ecoFilter;

  const columns: SortableColumn<LibraryItem>[] = [
    {
      header: "Name",
      sortKey: "name",
      accessor: (row) => <span className="font-medium">{row.name}</span>,
    },
    {
      header: "Ecosystem",
      accessor: (row) => (
        <span className="text-xs text-muted-foreground">
          {ECOSYSTEM_LABELS[row.ecosystem] ?? row.ecosystem}
        </span>
      ),
    },
    {
      header: "Status",
      sortKey: "collect_status",
      accessor: (row) => <StatusDot status={row.collect_status} />,
    },
    {
      header: "Used By",
      sortKey: "used_by_count",
      accessor: (row) => row.used_by_count,
    },
    {
      header: "Last Scanned",
      sortKey: "last_scanned_at",
      accessor: (row) => <TimeAgo date={row.last_scanned_at} />,
    },
  ];

  return (
    <div className="space-y-3">
      <PageHeader title="Libraries" description="All monitored dependency libraries" />

      {health && Object.keys(health.platforms).length > 0 && (() => {
        const allCounts = Object.values(health.platforms);
        const totalAll = allCounts.reduce((s, c) => s + (c.healthy ?? 0) + (c.unhealthy ?? 0), 0);
        const healthyAll = allCounts.reduce((s, c) => s + (c.healthy ?? 0), 0);
        const unhealthyAll = totalAll - healthyAll;
        return (
          <div className="flex items-center gap-4 rounded-md border bg-card px-4 py-3 overflow-x-auto">
            <div className="flex flex-col gap-0.5 pr-4 border-r min-w-[80px]">
              <span className="text-2xl font-bold tabular-nums">{totalAll}</span>
              <span className="text-[11px] text-muted-foreground">Total</span>
              <div className="flex items-center gap-3 mt-1">
                <span className="inline-flex items-center gap-1 text-[11px]">
                  <span className="inline-block h-2 w-2 rounded-full bg-emerald-500" />
                  {healthyAll}
                </span>
                <span className="inline-flex items-center gap-1 text-[11px]">
                  <span className="inline-block h-2 w-2 rounded-full bg-red-500" />
                  {unhealthyAll}
                </span>
              </div>
            </div>
            {Object.entries(health.platforms)
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([eco, counts]) => (
                <DonutChart
                  key={eco}
                  label={ECOSYSTEM_LABELS[eco] ?? eco}
                  healthy={counts.healthy ?? 0}
                  unhealthy={counts.unhealthy ?? 0}
                  active={ecoFilter === eco}
                  onClick={() => handleEcoClick(eco)}
                />
              ))}
          </div>
        );
      })()}

      {health && health.unhealthy_with_clients > 0 && (
        <button
          type="button"
          className="w-full flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800 dark:border-red-900 dark:bg-red-950/50 dark:text-red-300 hover:opacity-80 transition-opacity text-left"
          onClick={() => setStatusFilter("unhealthy")}
        >
          <AlertTriangle className="h-4 w-4 shrink-0" />
          {health.unhealthy_with_clients} unhealthy{" "}
          {health.unhealthy_with_clients === 1 ? "library" : "libraries"} used by client projects
        </button>
      )}

      {health && health.unhealthy_no_clients > 0 && (
        <button
          type="button"
          className="w-full flex items-center gap-2 rounded-md border border-orange-200 bg-orange-50 px-3 py-2 text-sm text-orange-800 dark:border-orange-900 dark:bg-orange-950/50 dark:text-orange-300 hover:opacity-80 transition-opacity text-left"
          onClick={() => setStatusFilter("unhealthy")}
        >
          <AlertTriangle className="h-4 w-4 shrink-0" />
          {health.unhealthy_no_clients} unhealthy{" "}
          {health.unhealthy_no_clients === 1 ? "library" : "libraries"} (unused)
        </button>
      )}

      {hasActiveFilter && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <span>Filtered:</span>
          {ecoFilter && (
            <span className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-xs font-medium text-foreground">
              {ECOSYSTEM_LABELS[ecoFilter] ?? ecoFilter}
              <button type="button" onClick={() => setEcoFilter(null)}>
                <X className="h-3 w-3" />
              </button>
            </span>
          )}
          {statusFilter && (
            <span className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-xs font-medium text-foreground">
              {statusFilter}
              <button type="button" onClick={() => setStatusFilter(null)}>
                <X className="h-3 w-3" />
              </button>
            </span>
          )}
          <button
            type="button"
            onClick={() => {
              setEcoFilter(null);
              setStatusFilter(null);
            }}
            className="text-xs hover:text-foreground transition-colors"
          >
            Clear all
          </button>
        </div>
      )}

      <PagedTable
        columns={columns}
        data={libraries.data}
        page={libraries.page}
        totalPages={libraries.totalPages}
        total={libraries.total}
        hasNext={libraries.hasNext}
        hasPrev={libraries.hasPrev}
        onNext={libraries.nextPage}
        onPrev={libraries.prevPage}
        isLoading={libraries.isLoading}
        pageSize={libraries.pageSize}
        onRowClick={(row) => router.push(`/library/${row.id}`)}
        keyExtractor={(row) => row.id}
        emptyTitle="No libraries"
        emptyDescription="No libraries are being monitored yet."
        sortBy={sortBy}
        sortDir={sortDir}
        onSort={handleSort}
      />
    </div>
  );
}
