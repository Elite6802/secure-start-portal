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
  Requested: { bg: "bg-secondary/60", text: "text-muted-foreground" },
  Queued: { bg: "bg-secondary/60", text: "text-muted-foreground" },
  Rejected: { bg: "bg-destructive/15", text: "text-destructive" },
  Failed: { bg: "bg-destructive/15", text: "text-destructive" },
  Investigating: { bg: "bg-warning/15", text: "text-warning" },
  Scheduled: { bg: "bg-muted", text: "text-muted-foreground" },
  Open: { bg: "bg-destructive/15", text: "text-destructive" },
  Covered: { bg: "bg-success/15", text: "text-success" },
  Partial: { bg: "bg-warning/15", text: "text-warning" },
  "Not Assessed": { bg: "bg-muted", text: "text-muted-foreground" },
};

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const config = statusConfig[status] || statusConfig.Open;
  return (
    <span className={cn("inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium", config.bg, config.text, className)}>
      {status}
    </span>
  );
}
