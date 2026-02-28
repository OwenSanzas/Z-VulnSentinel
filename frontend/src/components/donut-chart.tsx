"use client";

import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";

interface DonutChartProps {
  healthy: number;
  unhealthy: number;
  label: string;
  size?: number;
  active?: boolean;
  onClick?: () => void;
}

const COLORS = { healthy: "#22c55e", unhealthy: "#ef4444" } as const;

export function DonutChart({
  healthy,
  unhealthy,
  label,
  size = 80,
  active,
  onClick,
}: DonutChartProps) {
  const total = healthy + unhealthy;
  const data =
    total > 0
      ? [
          { name: "healthy", value: healthy },
          { name: "unhealthy", value: unhealthy },
        ].filter((d) => d.value > 0)
      : [{ name: "empty", value: 1 }];

  return (
    <button
      type="button"
      onClick={onClick}
      className={`flex flex-col items-center gap-1 rounded-lg px-3 py-2 transition-colors ${
        active
          ? "bg-accent ring-1 ring-ring"
          : "hover:bg-accent/50"
      }`}
    >
      <div className="relative" style={{ width: size, height: size }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              cx="50%"
              cy="50%"
              innerRadius="65%"
              outerRadius="100%"
              paddingAngle={total > 0 && healthy > 0 && unhealthy > 0 ? 3 : 0}
              strokeWidth={0}
            >
              {data.map((d) => (
                <Cell
                  key={d.name}
                  fill={
                    d.name === "empty"
                      ? "hsl(var(--muted))"
                      : COLORS[d.name as keyof typeof COLORS]
                  }
                />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <span className="absolute inset-0 flex items-center justify-center text-sm font-semibold tabular-nums">
          {total}
        </span>
      </div>
      <span className="text-[11px] text-muted-foreground truncate max-w-[90px] text-center">
        {label}
      </span>
    </button>
  );
}
