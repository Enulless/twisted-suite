import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

interface Props {
  counts: Record<string, number>;  // severity → count
  size?: number;
}

const ORDER = ["critical", "high", "medium", "low", "info"] as const;
const COLORS: Record<string, string> = {
  critical: "hsl(var(--sev-critical))",
  high: "hsl(var(--sev-high))",
  medium: "hsl(var(--sev-medium))",
  low: "hsl(var(--sev-low))",
  info: "hsl(var(--sev-info))",
};

export function SeverityDonut({ counts, size = 160 }: Props) {
  const data = ORDER.map((sev) => ({
    name: sev.charAt(0).toUpperCase() + sev.slice(1),
    value: counts[sev] ?? 0,
    color: COLORS[sev],
  })).filter((d) => d.value > 0);
  const total = data.reduce((acc, d) => acc + d.value, 0);

  if (total === 0) {
    return (
      <div
        className="flex items-center justify-center text-xs text-muted-foreground"
        style={{ width: size, height: size }}
      >
        no findings
      </div>
    );
  }
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <ResponsiveContainer>
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            innerRadius={size * 0.35}
            outerRadius={size * 0.5}
            paddingAngle={2}
            stroke="none"
          >
            {data.map((d, i) => (
              <Cell key={i} fill={d.color} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              background: "hsl(var(--card))",
              border: "1px solid hsl(var(--border))",
              borderRadius: 6,
              fontSize: 12,
            }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <div className="text-2xl font-bold">{total}</div>
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
          findings
        </div>
      </div>
    </div>
  );
}
