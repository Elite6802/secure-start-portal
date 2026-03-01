import { useEffect, useState } from "react";
import { PaginatedResponse, apiRequest, unwrapResults } from "@/lib/api";
import { ActivityLogItem } from "@/lib/types";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export default function ActivityLogAdmin() {
  const [entries, setEntries] = useState<ActivityLogItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    const data = await apiRequest<PaginatedResponse<ActivityLogItem>>("/internal/activity-log/");
    setEntries(unwrapResults<ActivityLogItem>(data));
    setLoading(false);
  };

  useEffect(() => {
    load().catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load activity log."));
  }, []);

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
    return Object.entries(serviceTypeLabels).reduce((text, [key, label]) => text.split(key).join(label), detail);
  };

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Activity Log</h1>
      <p className="text-sm text-muted-foreground mb-6">Internal audit log across all administrative actions.</p>

      {error && <p className="text-sm text-destructive mb-4">{error}</p>}

      <div className="glass-card rounded-xl overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Action</TableHead>
              <TableHead>User</TableHead>
              <TableHead>Organization</TableHead>
              <TableHead>Timestamp</TableHead>
              <TableHead>Detail</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={5} className="text-sm text-muted-foreground">Loading activity log...</TableCell>
              </TableRow>
            ) : (
              entries.map((entry) => (
                <TableRow key={entry.id}>
                  <TableCell className="font-medium">{entry.action}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{entry.user_email || entry.user || "-"}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{entry.organization_name || entry.organization}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{entry.timestamp}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{formatDetail(entry)}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

