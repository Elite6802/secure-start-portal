import { Button } from "@/components/ui/button";

interface EmptyStateProps {
  title: string;
  description: string;
  ctaLabel?: string;
  onAction?: () => void;
}

export function EmptyState({ title, description, ctaLabel = "Request baseline scan", onAction }: EmptyStateProps) {
  return (
    <div className="glass-card rounded-xl p-8 text-center">
      <h3 className="font-display text-lg font-semibold mb-2">{title}</h3>
      <p className="text-sm text-muted-foreground mb-6">{description}</p>
      <Button variant="outline" onClick={onAction}>{ctaLabel}</Button>
    </div>
  );
}
