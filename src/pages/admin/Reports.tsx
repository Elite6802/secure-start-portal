import { useEffect, useState } from "react";
import { PaginatedResponse, apiRequest, downloadFile, unwrapResults } from "@/lib/api";
import { Report } from "@/lib/types";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "@/components/ui/use-toast";

type SeverityCounts = {
  critical: number;
  high: number;
  moderate: number;
  low: number;
};

const emptyCounts = (): SeverityCounts => ({
  critical: 0,
  high: 0,
  moderate: 0,
  low: 0,
});

const parseSeveritySummary = (summary: string | null | undefined): SeverityCounts | null => {
  if (!summary) return null;
  const match = summary.match(/critical\s+(\d+).+high\s+(\d+).+moderate\s+(\d+).+low\s+(\d+)/i);
  if (!match) return null;
  return {
    critical: Number(match[1]),
    high: Number(match[2]),
    moderate: Number(match[3]),
    low: Number(match[4]),
  };
};

const severityFromMetadata = (metadata: Report["metadata"]): SeverityCounts | null => {
  if (!metadata || typeof metadata !== "object") return null;
  const summary = (metadata as Record<string, unknown>).severity_summary;
  if (!summary || typeof summary !== "object") return null;
  const raw = summary as Record<string, unknown>;
  return {
    critical: Number(raw.critical ?? 0),
    high: Number(raw.high ?? 0),
    moderate: Number(raw.moderate ?? 0),
    low: Number(raw.low ?? 0),
  };
};

const cloudAccountLabel = (report: Report) => {
  if (report.scope !== "cloud") return "-";
  if (!report.metadata || typeof report.metadata !== "object") return "-";
  const metadata = report.metadata as Record<string, unknown>;
  const name = metadata.cloud_account_name as string | undefined;
  const provider = metadata.cloud_provider as string | undefined;
  if (!name && !provider) return "-";
  return `${name || "Cloud account"}${provider ? ` (${String(provider).toUpperCase()})` : ""}`;
};

const SCOPE_LABELS: Record<string, string> = {
  web: "Web",
  api: "API",
  code: "Code",
  network: "Network",
  combined: "Combined",
  cloud: "Cloud",
};

const SERVICE_LABELS: Record<string, string> = {
  CODE_SECRETS_SCAN: "Code Secrets Scan",
  DEPENDENCY_VULN_SCAN: "Dependency Vulnerability Scan",
  CODE_COMPLIANCE_SCAN: "Code Standards Compliance",
  NETWORK_CONFIGURATION_SCAN: "Network Configuration Scan",
  WEB_EXPOSURE_SCAN: "Web Exposure Scan",
  API_SECURITY_SCAN: "API Security Scan",
  INFRASTRUCTURE_HARDENING_SCAN: "Infrastructure Hardening Scan",
  CLOUD_POSTURE_SCAN: "Cloud Posture Scan",
};

export default function ReportsAdmin() {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const data = await apiRequest<PaginatedResponse<Report>>("/internal/reports/");
      const results = unwrapResults<Report>(data).sort((a, b) => {
        const aTime = a.generated_at ? new Date(a.generated_at).getTime() : 0;
        const bTime = b.generated_at ? new Date(b.generated_at).getTime() : 0;
        return bTime - aTime;
      });
      setReports(results);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load reports.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleDownload = async (report: Report) => {
    try {
      await downloadFile(`/internal/reports/${report.id}/download/`, `aegis-report-${report.id}.pdf`);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to download report.";
      toast({
        title: "Download failed",
        description: message,
        variant: "destructive",
      });
    }
  };

  const handlePublish = async (report: Report) => {
    try {
      await apiRequest(`/internal/reports/${report.id}/publish/`, { method: "POST" });
      await load();
      toast({
        title: "Report delivered",
        description: "The report is now visible to the client.",
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to publish report.";
      toast({
        title: "Publish failed",
        description: message,
        variant: "destructive",
      });
    }
  };

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Reports</h1>
      <p className="text-sm text-muted-foreground mb-6">
        Archive of generated security reports across tenants and service requests.
      </p>

      {error && <p className="text-sm text-destructive mb-4">{error}</p>}

      <div className="glass-card rounded-xl overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Scope</TableHead>
              <TableHead>Organization</TableHead>
              <TableHead>Service Request</TableHead>
              <TableHead>Scan Job</TableHead>
              <TableHead>Cloud Account</TableHead>
              <TableHead>Severities</TableHead>
              <TableHead>Generated</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={9} className="text-sm text-muted-foreground">Loading reports...</TableCell>
              </TableRow>
            ) : reports.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="text-sm text-muted-foreground">
                  No reports generated yet.
                </TableCell>
              </TableRow>
            ) : (
              reports.map((report) => {
                const counts =
                  severityFromMetadata(report.metadata) ||
                  parseSeveritySummary(report.summary) ||
                  emptyCounts();
                return (
                  <TableRow key={report.id}>
                    <TableCell className="font-medium">{SCOPE_LABELS[report.scope] || report.scope}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{report.organization_name || "Unassigned"}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {report.service_request_type ? (SERVICE_LABELS[report.service_request_type] || report.service_request_type) : "-"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{report.scan_job_type ? `${report.scan_job_type} scan` : "-"}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{cloudAccountLabel(report)}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        <SeverityBadge level="Critical" count={counts.critical} />
                        <SeverityBadge level="High" count={counts.high} />
                        <SeverityBadge level="Medium" count={counts.moderate} />
                        <SeverityBadge level="Low" count={counts.low} />
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{report.generated_at?.slice(0, 10)}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {report.client_visible ? "Delivered" : "Internal"}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex flex-wrap items-center justify-end gap-2">
                        <Button variant="outline" size="sm" onClick={() => handleDownload(report)}>
                          Download PDF
                        </Button>
                        <Button
                          size="sm"
                          onClick={() => handlePublish(report)}
                          disabled={report.client_visible}
                        >
                          {report.client_visible ? "Sent" : "Send to Client"}
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
