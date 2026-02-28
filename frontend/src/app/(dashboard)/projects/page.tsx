"use client";

import { useRouter } from "next/navigation";
import Link from "next/link";
import { usePagedQuery } from "@/hooks/use-paged-query";
import { queryKeys } from "@/lib/query-keys";
import { PagedTable } from "@/components/paged-table";
import type { Column } from "@/components/data-table";
import { TimeAgo } from "@/components/time-ago";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/page-header";
import { Plus, Loader2, AlertCircle } from "lucide-react";

interface ProjectItem {
  id: string;
  name: string;
  organization: string | null;
  repo_url: string;
  deps_count: number;
  vuln_count: number;
  scan_status: string;
  monitoring_since: string;
  last_update_at: string | null;
  created_at: string;
}

export default function ProjectsPage() {
  const router = useRouter();

  const projects = usePagedQuery<ProjectItem>({
    queryKey: queryKeys.projects.all,
    path: "/api/v1/projects/",
  });

  const columns: Column<ProjectItem>[] = [
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
    {
      header: "Deps",
      accessor: (row) =>
        row.scan_status === "pending" || row.scan_status === "scanning" ? (
          <Loader2 className="h-3 w-3 animate-spin text-muted-foreground" />
        ) : row.scan_status === "error" ? (
          <AlertCircle className="h-3 w-3 text-red-500" />
        ) : (
          row.deps_count
        ),
    },
    {
      header: "Vulns",
      accessor: (row) =>
        row.vuln_count > 0 ? (
          <Badge className="bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/25">{row.vuln_count}</Badge>
        ) : (
          <span className="text-muted-foreground">0</span>
        ),
    },
    { header: "Since", accessor: (row) => <TimeAgo date={row.monitoring_since} /> },
    { header: "Last Update", accessor: (row) => <TimeAgo date={row.last_update_at} /> },
  ];

  return (
    <div className="space-y-3">
      <PageHeader
        title="Projects"
        description="All monitored client projects"
        actions={
          <Button asChild size="sm" className="h-7 text-xs">
            <Link href="/projects/new">
              <Plus className="h-3 w-3 mr-1" />
              New Project
            </Link>
          </Button>
        }
      />
      <PagedTable
        columns={columns}
        data={projects.data}
        page={projects.page}
        totalPages={projects.totalPages}
        total={projects.total}
        hasNext={projects.hasNext}
        hasPrev={projects.hasPrev}
        onNext={projects.nextPage}
        onPrev={projects.prevPage}
        isLoading={projects.isLoading}
        pageSize={projects.pageSize}
        onRowClick={(row) => router.push(`/project/${row.id}`)}
        keyExtractor={(row) => row.id}
        emptyTitle="No projects"
        emptyDescription="No projects have been added yet."
      />
    </div>
  );
}
