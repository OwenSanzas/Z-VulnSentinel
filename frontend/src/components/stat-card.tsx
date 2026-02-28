import type { LucideIcon } from "lucide-react";

interface StatCardProps {
  label: string;
  value: string | number;
  icon: LucideIcon;
  iconColor?: string;
}

export function StatCard({ label, value, icon: Icon, iconColor = "text-primary" }: StatCardProps) {
  return (
    <div className="rounded-md border bg-card px-4 py-3 flex items-center justify-between">
      <div>
        <div className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">{label}</div>
        <div className="text-xl font-semibold text-foreground mt-0.5">{value}</div>
      </div>
      <Icon className={`h-4 w-4 ${iconColor}`} />
    </div>
  );
}
