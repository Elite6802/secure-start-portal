import { useEffect, useState } from "react";
import { useOutletContext } from "react-router-dom";
import { EmptyState } from "@/components/dashboard/EmptyState";
import { RoleRestricted } from "@/components/dashboard/RoleRestricted";
import { ServiceRequestCard } from "@/components/dashboard/ServiceRequestCard";
import { PaginatedResponse, apiRequest, unwrapResults } from "@/lib/api";
import { ActivityLogItem } from "@/lib/types";

export default function ActivityLog() {
  const { accessRole } = useOutletContext<{ role: string; accessRole?: string | null }>();
  const restricted = accessRole ? accessRole !== "Security Lead" : true;
  const [activityLog, setActivityLog] = useState<ActivityLogItem[]>([]);
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
        const data = await apiRequest<PaginatedResponse<ActivityLogItem>>("/activity-log/");
        setActivityLog(unwrapResults<ActivityLogItem>(data));
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Failed to load activity log.");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [accessRole, restricted]);

  const serviceTypeLabels: Record<string, string> = {
    CODE_SECRETS_SCAN: "Code Secrets Scan",
    DEPENDENCY_VULN_SCAN: "Dependency Vulnerability Scan",
    CODE_COMPLIANCE_SCAN: "Code Standards Compliance",
    CODE_COMPLIANCE_PYTHON: "Python PEP8 Compliance",
    CODE_COMPLIANCE_HTML: "HTML Standards Compliance",
    CODE_COMPLIANCE_CSS: "CSS Standards Compliance",
    CODE_COMPLIANCE_JAVASCRIPT: "JavaScript Standards Compliance",
    CODE_COMPLIANCE_REACT: "React Standards Compliance",
    NETWORK_CONFIGURATION_SCAN: "Network Configuration Scan",
    WEB_EXPOSURE_SCAN: "Web Exposure Scan",
    API_SECURITY_SCAN: "API Security Scan",
    INFRASTRUCTURE_HARDENING_SCAN: "Infrastructure Hardening Scan",
  };

  const formatDetail = (entry: ActivityLogItem) => {
    const detail = entry.detail ?? (typeof entry.metadata?.detail === "string" ? entry.metadata.detail : "");
    if (!detail) {
      return "Event recorded.";
    }
    const mapped = Object.entries(serviceTypeLabels).reduce((text, [key, label]) => text.split(key).join(label), detail);
    return mapped;
  };

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Activity and Audit Log</h1>
      <p className="text-sm text-muted-foreground mb-8">Chronological record of scans, reports, and incident activity.</p>

      <ServiceRequestCard
        title="Request Audit Export"
        description="Request an audit log export for a defined scope. The platform team will validate and deliver an export package."
        serviceType="DEPENDENCY_VULN_SCAN"
        targetField="domain_url"
        allowedRoles={["Security Lead"]}
        accessRole={accessRole}
        helperText="Requests are reviewed by the platform security team."
        targetPlaceholder="Scope (time range, system, or environment)"
        justificationPlaceholder="Define the audit window and systems required for the export."
      />

      {!accessRole && <p className="text-sm text-muted-foreground mb-6">Loading access profile...</p>}
      {accessRole && restricted && (
        <RoleRestricted
          title="Audit log restricted"
          description="Audit logs are available to Security Lead users for operational accountability."
        />
      )}
      {accessRole && !restricted && (
        <>
          {loading && <p className="text-sm text-muted-foreground mb-6">Loading activity log...</p>}
          {error && <p className="text-sm text-destructive mb-6">{error}</p>}

          {activityLog.length === 0 && !loading ? (
            <EmptyState
              title="No activity captured"
              description="Once scans and incidents are active, this timeline will record operational events with timestamps. Audit logs help demonstrate continuous monitoring and response diligence."
            />
          ) : (
            <div className="space-y-4">
              {activityLog.map((entry) => (
                <div key={entry.id} className="relative pl-10">
                  <span className="absolute left-3 top-6 h-2.5 w-2.5 rounded-full bg-primary" />
                  <div className="glass-card rounded-xl p-5">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-semibold">{entry.action}</p>
                        <p className="text-xs text-muted-foreground">
                          {entry.organization_name || entry.organization}
                          {entry.user_email ? ` · ${entry.user_email}` : ""}
                        </p>
                      </div>
                      <span className="text-xs text-muted-foreground font-mono">{entry.timestamp}</span>
                    </div>
                    <p className="text-sm text-muted-foreground mt-2">{formatDetail(entry)}</p>
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
