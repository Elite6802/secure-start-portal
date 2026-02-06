import { incidents } from "@/data/mockData";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { AlertTriangle, Clock } from "lucide-react";

export default function Incidents() {
  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Incidents</h1>
      <p className="text-sm text-muted-foreground mb-8">Security incidents and their resolution status.</p>

      <div className="space-y-4">
        {incidents.map((incident) => (
          <div key={incident.id} className="glass-card rounded-xl p-6">
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-start gap-3">
                <div className="rounded-lg bg-destructive/10 p-2 mt-0.5">
                  <AlertTriangle className="h-5 w-5 text-destructive" />
                </div>
                <div>
                  <h3 className="font-display font-semibold text-sm">{incident.title}</h3>
                  <div className="flex items-center gap-2 mt-1">
                    <SeverityBadge level={incident.severity} />
                    <StatusBadge status={incident.status} />
                  </div>
                </div>
              </div>
              <span className="text-xs text-muted-foreground font-mono">{incident.id}</span>
            </div>

            <div className="ml-12 space-y-2">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Clock className="h-3.5 w-3.5" />
                Created: {incident.created}
                {incident.resolved && <> · Resolved: {incident.resolved}</>}
              </div>
              <p className="text-sm text-muted-foreground">{incident.notes}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
