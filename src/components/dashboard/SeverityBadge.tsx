import { cn } from "@/lib/utils";

interface SeverityBadgeProps {
  level: "Critical" | "High" | "Medium" | "Low" | string;
  count?: number;
  className?: string;
}

const severityConfig: Record<string, { bg: string; text: string }> = {
  Critical: { bg: "bg-destructive/15", text: "text-destructive" },
  High: { bg: "bg-destructive/15", text: "text-destructive" },
  Medium: { bg: "bg-warning/15", text: "text-warning" },
  Low: { bg: "bg-primary/15", text: "text-primary" },
};

export function SeverityBadge({ level, count, className }: SeverityBadgeProps) {
  const config = severityConfig[level] || severityConfig.Low;
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium", config.bg, config.text, className)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", level === "Critical" || level === "High" ? "bg-destructive" : level === "Medium" ? "bg-warning" : "bg-primary")} />
      {level}
      {count !== undefined && <span className="font-semibold">{count}</span>}
    </span>
  );
}
