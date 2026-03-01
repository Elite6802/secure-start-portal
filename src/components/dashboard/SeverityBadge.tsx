import { cn } from "@/lib/utils";

interface SeverityBadgeProps {
  level: "Critical" | "High" | "Medium" | "Low" | string;
  count?: number;
  className?: string;
}

const severityConfig: Record<string, { bg: string; text: string }> = {
  Critical: { bg: "bg-destructive/15", text: "text-destructive" },
  High: { bg: "bg-orange-500/15", text: "text-orange-500" },
  Medium: { bg: "bg-warning/15", text: "text-warning" },
  Moderate: { bg: "bg-warning/15", text: "text-warning" },
  Low: { bg: "bg-primary/15", text: "text-primary" },
};

export function SeverityBadge({ level, count, className }: SeverityBadgeProps) {
  const config = severityConfig[level] || severityConfig.Low;
  const labelMap: Record<string, string> = {
    High: "High",
    Medium: "Moderate",
    Low: "Low",
    Critical: "Critical",
    Moderate: "Moderate",
  };
  const label = labelMap[level] ?? level;
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium", config.bg, config.text, className)}>
      <span
        className={cn(
          "h-1.5 w-1.5 rounded-full",
          level === "Critical"
            ? "bg-destructive"
            : level === "High"
            ? "bg-orange-500"
            : level === "Medium" || level === "Moderate"
            ? "bg-warning"
            : "bg-primary"
        )}
      />
      {label}
      {count !== undefined && <span className="font-semibold">{count}</span>}
    </span>
  );
}
