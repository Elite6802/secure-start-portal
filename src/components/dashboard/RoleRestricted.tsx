import { ShieldAlert } from "lucide-react";

interface RoleRestrictedProps {
  title: string;
  description: string;
}

export function RoleRestricted({ title, description }: RoleRestrictedProps) {
  return (
    <div className="glass-card rounded-xl p-8 text-center">
      <div className="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-warning/15 text-warning">
        <ShieldAlert className="h-5 w-5" />
      </div>
      <h3 className="font-display text-lg font-semibold mb-2">{title}</h3>
      <p className="text-sm text-muted-foreground">{description}</p>
    </div>
  );
}
