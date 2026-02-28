import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const severityColors: Record<string, string> = {
  critical: "bg-red-500/15 text-red-600 dark:text-red-400 border-red-500/25",
  high: "bg-orange-500/15 text-orange-600 dark:text-orange-400 border-orange-500/25",
  medium: "bg-yellow-500/15 text-yellow-700 dark:text-yellow-400 border-yellow-500/25",
  low: "bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/25",
};

export function SeverityBadge({ severity }: { severity: string | null | undefined }) {
  if (!severity) return <Badge variant="secondary">Unknown</Badge>;
  return (
    <Badge className={cn(severityColors[severity] || "")}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </Badge>
  );
}
