import { formatDistanceToNow } from "date-fns";

export function TimeAgo({ date }: { date: string | null | undefined }) {
  if (!date) return <span className="text-muted-foreground">-</span>;
  return (
    <span title={new Date(date).toLocaleString()}>
      {formatDistanceToNow(new Date(date), { addSuffix: true })}
    </span>
  );
}
