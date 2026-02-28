"use client";

import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DataTable, type Column } from "@/components/data-table";
import { TimeAgo } from "@/components/time-ago";
import { Badge } from "@/components/ui/badge";
import { usePaginatedQuery } from "@/hooks/use-paginated-query";
import { useRouter } from "next/navigation";
import { PageHeader } from "@/components/page-header";
import { StatCard } from "@/components/stat-card";
import { SkeletonCard, Skeleton } from "@/components/skeleton";
import { FolderOpen, ShieldAlert, FileWarning, ShieldCheck, Wrench } from "lucide-react";

interface DiskUsage {
  total_gb: number;
  used_gb: number;
  percent: number;
}

interface DashboardStats {
  projects_count: number;
  libraries_count: number;
  vuln_recorded: number;
  vuln_reported: number;
  vuln_confirmed: number;
  vuln_fixed: number;
  disk: DiskUsage;
}

interface ProjectItem {
  id: string;
  name: string;
  organization: string | null;
  deps_count: number;
  vuln_count: number;
  last_update_at: string | null;
}

interface EventItem {
  id: string;
  library_id: string;
  library_name: string;
  type: string;
  title: string;
  classification: string | null;
  is_bugfix: boolean;
  event_at: string | null;
  created_at: string;
}

function DiskDonut({ disk }: { disk: DiskUsage }) {
  const r = 28;
  const stroke = 6;
  const c = 2 * Math.PI * r;
  const filled = c * (disk.percent / 100);
  const warn = disk.percent > 85;

  return (
    <div className="rounded-md border bg-card px-4 py-3 flex items-center gap-4">
      <svg width="64" height="64" viewBox="0 0 64 64" className="shrink-0">
        <circle cx="32" cy="32" r={r} fill="none" stroke="currentColor" strokeWidth={stroke}
          className="text-muted/60" />
        <circle cx="32" cy="32" r={r} fill="none"
          stroke="currentColor" strokeWidth={stroke}
          strokeDasharray={`${filled} ${c - filled}`}
          strokeDashoffset={c / 4}
          strokeLinecap="round"
          className={warn ? "text-red-500" : "text-primary"}
        />
        <text x="32" y="34" textAnchor="middle" className="fill-foreground text-[11px] font-semibold">
          {disk.percent}%
        </text>
      </svg>
      <div>
        <div className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Node Storage</div>
        <div className="text-sm font-semibold text-foreground mt-0.5">
          {disk.used_gb}G / {disk.total_gb}G
        </div>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const router = useRouter();

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: queryKeys.dashboard,
    queryFn: () => apiFetch<DashboardStats>("/api/v1/stats/dashboard"),
    refetchInterval: 30_000,
  });

  const projects = usePaginatedQuery<ProjectItem>({
    queryKey: queryKeys.projects.all,
    path: "/api/v1/projects/",
    pageSize: 10,
  });

  const events = usePaginatedQuery<EventItem>({
    queryKey: queryKeys.events.all,
    path: "/api/v1/events/",
    pageSize: 15,
  });

  const statCards = [
    { label: "Projects", value: stats?.projects_count ?? 0, icon: FolderOpen },
    { label: "Recorded", value: stats?.vuln_recorded ?? 0, icon: ShieldAlert, iconColor: "text-blue-500" },
    { label: "Reported", value: stats?.vuln_reported ?? 0, icon: FileWarning, iconColor: "text-yellow-500" },
    { label: "Confirmed", value: stats?.vuln_confirmed ?? 0, icon: ShieldCheck, iconColor: "text-orange-500" },
    { label: "Fixed", value: stats?.vuln_fixed ?? 0, icon: Wrench, iconColor: "text-green-500" },
  ];

  const projectColumns: Column<ProjectItem>[] = [
    {
      header: "Project",
      accessor: (row) => (
        <div>
          <span className="font-medium">{row.name}</span>
          {row.organization && (
            <span className="text-muted-foreground ml-1.5">{row.organization}</span>
          )}
        </div>
      ),
    },
    { header: "Deps", accessor: (row) => row.deps_count },
    {
      header: "Vulns",
      accessor: (row) =>
        row.vuln_count > 0 ? (
          <Badge className="bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/25">{row.vuln_count}</Badge>
        ) : (
          <span className="text-muted-foreground">0</span>
        ),
    },
    { header: "Last Update", accessor: (row) => <TimeAgo date={row.last_update_at} /> },
  ];

  const eventColumns: Column<EventItem>[] = [
    { header: "Library", accessor: (row) => row.library_name },
    { header: "Title", accessor: (row) => <span className="truncate max-w-xs block">{row.title}</span> },
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
    { header: "Time", accessor: (row) => <TimeAgo date={row.event_at || row.created_at} /> },
  ];

  return (
    <div className="space-y-4">
      <PageHeader title="Dashboard" />

      <div className="grid gap-3 grid-cols-6">
        {statsLoading
          ? Array.from({ length: 5 }).map((_, i) => <SkeletonCard key={i} />)
          : statCards.map((card) => (
              <StatCard key={card.label} {...card} />
            ))}
        {statsLoading ? (
          <div className="rounded-md border bg-card px-4 py-3 flex items-center gap-4">
            <Skeleton className="h-16 w-16 rounded-full" />
            <div className="space-y-2">
              <Skeleton className="h-3 w-20" />
              <Skeleton className="h-4 w-24" />
            </div>
          </div>
        ) : stats ? (
          <DiskDonut disk={stats.disk} />
        ) : null}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Client Projects</CardTitle>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={projectColumns}
              data={projects.data}
              hasMore={projects.hasMore}
              onLoadMore={projects.loadMore}
              isLoading={projects.isLoading}
              onRowClick={(row) => router.push(`/project/${row.id}`)}
              keyExtractor={(row) => row.id}
              emptyTitle="No projects"
              emptyDescription="No projects have been added yet."
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent Activity</CardTitle>
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
              emptyTitle="No activity"
              emptyDescription="No events have been recorded yet."
            />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
