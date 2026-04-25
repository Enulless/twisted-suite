import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

interface Props {
  buckets: Record<string, number>;  // tier → count
}

const TIER_ORDER = ["critical", "high", "medium", "low", "info", "none"] as const;
const COLORS: Record<string, string> = {
  critical: "hsl(var(--sev-critical))",
  high: "hsl(var(--sev-high))",
  medium: "hsl(var(--sev-medium))",
  low: "hsl(var(--sev-low))",
  info: "hsl(var(--sev-info))",
  none: "hsl(var(--muted-foreground))",
};

export function RiskHistogram({ buckets }: Props) {
  const data = TIER_ORDER.map((t) => ({
    tier: t,
    count: buckets[t] ?? 0,
  }));
  const total = data.reduce((acc, d) => acc + d.count, 0);
  if (total === 0) {
    return (
      <div className="text-xs text-muted-foreground p-4">no assets to chart</div>
    );
  }
  return (
    <div className="w-full h-40">
      <ResponsiveContainer>
        <BarChart data={data} margin={{ top: 5, right: 8, left: 0, bottom: 5 }}>
          <CartesianGrid strokeDasharray="2 4" stroke="hsl(var(--border))" />
          <XAxis dataKey="tier" stroke="hsl(var(--muted-foreground))"
                 fontSize={10} tickLine={false} axisLine={false} />
          <YAxis allowDecimals={false} stroke="hsl(var(--muted-foreground))"
                 fontSize={10} tickLine={false} axisLine={false} width={28} />
          <Tooltip
            contentStyle={{
              background: "hsl(var(--card))",
              border: "1px solid hsl(var(--border))",
              borderRadius: 6,
              fontSize: 12,
            }}
            cursor={{ fill: "hsl(var(--accent))" }}
          />
          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
            {data.map((d, i) => <Cell key={i} fill={COLORS[d.tier]} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
