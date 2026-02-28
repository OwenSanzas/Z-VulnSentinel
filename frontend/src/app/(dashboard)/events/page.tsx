"use client";

import { useRouter } from "next/navigation";
import { usePaginatedQuery } from "@/hooks/use-paginated-query";
import { queryKeys } from "@/lib/query-keys";
import { DataTable, type Column } from "@/components/data-table";
import { TimeAgo } from "@/components/time-ago";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/page-header";

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

export default function EventsPage() {
  const router = useRouter();

  const events = usePaginatedQuery<EventItem>({
    queryKey: queryKeys.events.all,
    path: "/api/v1/events/",
  });

  const columns: Column<EventItem>[] = [
    { header: "Library", accessor: (row) => row.library_name },
    { header: "Type", accessor: (row) => <Badge variant="outline">{row.type}</Badge> },
    { header: "Title", accessor: (row) => <span className="truncate max-w-md block">{row.title}</span> },
    {
      header: "Classification",
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
    <div className="space-y-3">
      <PageHeader title="Events" description="All captured commits, PRs, tags, and issues" />
      <DataTable
        columns={columns}
        data={events.data}
        total={events.total}
        hasMore={events.hasMore}
        onLoadMore={events.loadMore}
        isLoading={events.isLoading}
        onRowClick={(row) => router.push(`/event/${row.id}`)}
        keyExtractor={(row) => row.id}
        emptyTitle="No events"
        emptyDescription="No events have been recorded yet."
      />
    </div>
  );
}
