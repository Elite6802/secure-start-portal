import { useEffect, useState } from "react";
import { useOutletContext } from "react-router-dom";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { RoleRestricted } from "@/components/dashboard/RoleRestricted";
import { ServiceRequestCard } from "@/components/dashboard/ServiceRequestCard";
import { AlertTriangle, Clock } from "lucide-react";
import { EmptyState } from "@/components/dashboard/EmptyState";
import { PaginatedResponse, apiRequest, unwrapResults } from "@/lib/api";
import { Incident } from "@/lib/types";

export default function Incidents() {
  const { accessRole } = useOutletContext<{ role: string; accessRole?: string | null }>();
  const restricted = accessRole ? !["Security Lead", "Executive"].includes(accessRole) : true;
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        if (!accessRole || restricted) {
          setLoading(false);
          setError(null);
          return;
        }
        setLoading(true);
        const data = await apiRequest<PaginatedResponse<Incident>>("/incidents/");
        setIncidents(unwrapResults<Incident>(data));
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Failed to load incidents.");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [accessRole, restricted]);

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Security Incidents</h1>
      <p className="text-sm text-muted-foreground mb-8">Incident intake, investigation, and resolution status across monitored assets.</p>

      <ServiceRequestCard
        title="Request Incident Review"
        description="Escalate a potential incident for security review. The platform team will validate and update your incident timeline."
        serviceType="NETWORK_CONFIGURATION_SCAN"
        targetField="domain_url"
        allowedRoles={["Security Lead"]}
        accessRole={accessRole}
        helperText="Requests are reviewed by the platform security team."
        targetPlaceholder="Affected system, asset, or indicator"
        justificationPlaceholder="Provide incident context, impact, and supporting indicators."
      />

      {!accessRole && <p className="text-sm text-muted-foreground mb-6">Loading access profile...</p>}
      {accessRole && restricted && (
        <RoleRestricted
          title="Incident response view restricted"
          description="Incident timelines are available to Security Lead and Executive roles for response oversight."
        />
      )}
      {accessRole && !restricted && (
        <>
          {loading && <p className="text-sm text-muted-foreground mb-6">Loading incidents...</p>}
          {error && <p className="text-sm text-destructive mb-6">{error}</p>}

          {incidents.length === 0 && !loading ? (
            <EmptyState
              title="No incidents reported"
              description="When incidents are detected, this timeline will show severity, response status, and remediation notes. Incident tracking is essential for audit evidence and operational readiness."
            />
          ) : (
            <div className="space-y-4">
              {incidents.map((incident) => (
                <div key={incident.id} className="glass-card rounded-xl p-6">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-start gap-3">
                      <div className="rounded-lg bg-destructive/10 p-2 mt-0.5">
                        <AlertTriangle className="h-5 w-5 text-destructive" />
                      </div>
                      <div>
                        <h3 className="font-display font-semibold text-sm">{incident.description}</h3>
                        <div className="flex items-center gap-2 mt-1">
                          <SeverityBadge level={incident.severity === "moderate" ? "Medium" : incident.severity} />
                          <StatusBadge status={incident.status === "open" ? "Open" : incident.status === "investigating" ? "Investigating" : "Resolved"} />
                        </div>
                      </div>
                    </div>
                    <span className="text-xs text-muted-foreground font-mono">{incident.id}</span>
                  </div>

                  <div className="ml-12 space-y-2">
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <Clock className="h-3.5 w-3.5" />
                      Detected: {incident.detected_at}
                      {incident.resolved_at && <> - Resolved: {incident.resolved_at}</>}
                    </div>
                    <p className="text-sm text-muted-foreground">Status updated via incident workflow.</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
