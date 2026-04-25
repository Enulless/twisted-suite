import { cn } from "@/lib/utils";

interface Props {
  pct: number;            // 0.0 - 1.0
  label?: string;
  className?: string;
}

export function ProgressDots({ pct, label, className }: Props) {
  const filled = Math.round(pct * 10);
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <div className="flex items-center gap-0.5">
        {Array.from({ length: 10 }).map((_, i) => (
          <span
            key={i}
            className={cn(
              "h-1.5 w-3 rounded-sm",
              i < filled ? "bg-primary" : "bg-muted",
            )}
          />
        ))}
      </div>
      <span className="text-xs font-medium tabular-nums">
        {Math.round(pct * 100)}%
      </span>
      {label && (
        <span className="text-xs text-muted-foreground">{label}</span>
      )}
    </div>
  );
}
