import { cn } from "@/lib/utils";

interface StatusBadgeProps {
  status: string;
  className?: string;
}

const statusConfig: Record<string, { bg: string; text: string }> = {
  Completed: { bg: "bg-success/15", text: "text-success" },
  Monitored: { bg: "bg-success/15", text: "text-success" },
  Resolved: { bg: "bg-success/15", text: "text-success" },
  "In Progress": { bg: "bg-primary/15", text: "text-primary" },
  Investigating: { bg: "bg-warning/15", text: "text-warning" },
  Scheduled: { bg: "bg-muted", text: "text-muted-foreground" },
  Open: { bg: "bg-destructive/15", text: "text-destructive" },
};

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const config = statusConfig[status] || statusConfig.Open;
  return (
    <span className={cn("inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium", config.bg, config.text, className)}>
      {status}
    </span>
  );
}
