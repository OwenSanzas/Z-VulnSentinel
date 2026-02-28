import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const statusColors: Record<string, string> = {
  recorded: "bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/25",
  reported: "bg-yellow-500/15 text-yellow-700 dark:text-yellow-400 border-yellow-500/25",
  confirmed: "bg-orange-500/15 text-orange-600 dark:text-orange-400 border-orange-500/25",
  fixed: "bg-green-500/15 text-green-600 dark:text-green-400 border-green-500/25",
  not_affect: "bg-secondary text-muted-foreground border-transparent",
};

const pipelineColors: Record<string, string> = {
  pending: "bg-secondary text-muted-foreground border-transparent",
  path_searching: "bg-purple-500/15 text-purple-600 dark:text-purple-400 border-purple-500/25",
  poc_generating: "bg-indigo-500/15 text-indigo-600 dark:text-indigo-400 border-indigo-500/25",
  verified: "bg-green-500/15 text-green-600 dark:text-green-400 border-green-500/25",
  not_affect: "bg-secondary text-muted-foreground border-transparent",
};

const pipelineLabels: Record<string, string> = {
  pending: "Pending",
  path_searching: "Path Searching",
  poc_generating: "PoC Generating",
  verified: "Verified",
  not_affect: "Not Affected",
};

const statusLabels: Record<string, string> = {
  recorded: "Recorded",
  reported: "Reported",
  confirmed: "Confirmed",
  fixed: "Fixed",
  not_affect: "Not Affected",
};

export function StatusBadge({ status }: { status: string | null | undefined }) {
  if (!status) return <Badge variant="secondary">-</Badge>;
  return (
    <Badge className={cn(statusColors[status] || "")}>
      {statusLabels[status] || status}
    </Badge>
  );
}

export function PipelineBadge({ status }: { status: string }) {
  return (
    <Badge className={cn(pipelineColors[status] || "")}>
      {pipelineLabels[status] || status}
    </Badge>
  );
}
