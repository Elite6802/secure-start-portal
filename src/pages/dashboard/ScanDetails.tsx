import { useEffect, useMemo, useState } from "react";
import { useNavigate, useOutletContext, useParams } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/dashboard/EmptyState";
import { RoleRestricted } from "@/components/dashboard/RoleRestricted";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { PaginatedResponse, apiRequest, downloadFile, unwrapResults } from "@/lib/api";
import { CodeFinding, NetworkFinding, Report, ScanJob } from "@/lib/types";
import { toast } from "@/components/ui/use-toast";

const scanTypeLabels: Record<string, string> = {
  web: "Web Scan",
  api: "API Scan",
  code: "Code Security Scan",
  network: "Network Exposure Scan",
  infrastructure: "Infrastructure Scan",
};

const statusLabels: Record<string, string> = {
  queued: "Queued",
  running: "In Progress",
  completed: "Completed",
  failed: "Failed",
};

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

const tallyFindings = (code: CodeFinding[], network: NetworkFinding[]): SeverityCounts => {
  const counts = emptyCounts();
  const add = (severity?: string | null) => {
    if (!severity) return;
    const key = severity.toLowerCase() as keyof SeverityCounts;
    if (key in counts) counts[key] += 1;
  };
  code.forEach((finding) => add(finding.severity));
  network.forEach((finding) => add(finding.severity));
  return counts;
};

export default function ScanDetails() {
  const { accessRole } = useOutletContext<{ role: string; accessRole?: string | null }>();
  const restricted = accessRole ? accessRole !== "Security Lead" : true;
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState<ScanJob | null>(null);
  const [reports, setReports] = useState<Report[]>([]);
  const [codeFindings, setCodeFindings] = useState<CodeFinding[]>([]);
  const [networkFindings, setNetworkFindings] = useState<NetworkFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      if (!id) {
        setError("Scan not found.");
        setLoading(false);
        return;
      }
      if (!accessRole || restricted) {
        setLoading(false);
        return;
      }
      try {
        setLoading(true);
        const [scanData, reportData, codeData, networkData] = await Promise.all([
          apiRequest<ScanJob>(`/scan-jobs/${id}/`),
          apiRequest<PaginatedResponse<Report>>(`/reports/?scan_job=${id}`),
          apiRequest<PaginatedResponse<CodeFinding>>(`/code-findings/?scan_job=${id}`),
          apiRequest<PaginatedResponse<NetworkFinding>>(`/network-findings/?scan_job=${id}`),
        ]);
        setScan(scanData);
        setReports(unwrapResults<Report>(reportData));
        setCodeFindings(unwrapResults<CodeFinding>(codeData));
        setNetworkFindings(unwrapResults<NetworkFinding>(networkData));
        setError(null);
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Failed to load scan details.");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [accessRole, restricted, id]);

  const severityCounts = useMemo(() => {
    if (scan?.findings_summary) {
      return scan.findings_summary;
    }
    return tallyFindings(codeFindings, networkFindings);
  }, [scan?.findings_summary, codeFindings, networkFindings]);

  const totalFindings = useMemo(() => {
    if (scan?.findings_total !== undefined && scan?.findings_total !== null) {
      return scan.findings_total;
    }
    return codeFindings.length + networkFindings.length;
  }, [scan?.findings_total, codeFindings.length, networkFindings.length]);

  const handleDownload = async (report: Report) => {
    try {
      await downloadFile(`/reports/${report.id}/download/`, `aegis-report-${report.id}.pdf`);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to download report.";
      toast({ title: "Download failed", description: message, variant: "destructive" });
    }
  };

  if (!accessRole) {
    return <p className="text-sm text-muted-foreground">Loading access profile...</p>;
  }

  if (restricted) {
    return (
      <RoleRestricted
        title="Scan details restricted"
        description="Scan transparency data is available to Security Lead users for operational visibility."
      />
    );
  }

  if (loading) {
    return <p className="text-sm text-muted-foreground">Loading scan details...</p>;
  }

  if (error || !scan) {
    return (
      <EmptyState
        title="Scan details unavailable"
        description={error || "This scan could not be loaded."}
        ctaLabel="Back to scans"
        onAction={() => navigate("/dashboard/scans")}
      />
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-xs text-muted-foreground">Scan Details</p>
          <h1 className="font-display text-2xl font-bold">{scanTypeLabels[scan.scan_type] || scan.scan_type}</h1>
          <p className="text-sm text-muted-foreground">{scan.organization_name || scan.organization}</p>
        </div>
        <div className="flex items-center gap-2">
          <StatusBadge status={statusLabels[scan.status] || scan.status} />
          {scan.report_id && (
            <Button size="sm" variant="outline" onClick={() => handleDownload({ id: scan.report_id } as Report)}>
              Download Report
            </Button>
          )}
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <div className="glass-card rounded-xl p-4">
          <p className="text-xs text-muted-foreground">Scope</p>
          <p className="text-sm font-medium">{scan.scope_summary || scan.asset_name || scan.repository_url || "-"}</p>
          <div className="mt-2 text-xs text-muted-foreground space-y-1">
            <p>Assets scanned: {scan.assets_scanned ?? 0}</p>
            <p>Files scanned: {scan.files_scanned ?? 0}</p>
          </div>
        </div>
        <div className="glass-card rounded-xl p-4">
          <p className="text-xs text-muted-foreground">Timing</p>
          <div className="mt-2 text-xs text-muted-foreground space-y-1">
            <p>Started: {scan.started_at || "Not started"}</p>
            <p>Completed: {scan.completed_at || "Not completed"}</p>
            <p>Duration: {scan.duration_seconds ? `${scan.duration_seconds}s` : "N/A"}</p>
          </div>
        </div>
        <div className="glass-card rounded-xl p-4">
          <p className="text-xs text-muted-foreground">Findings</p>
          <div className="mt-2 flex flex-wrap gap-2">
            <SeverityBadge level="Critical" count={severityCounts.critical} />
            <SeverityBadge level="High" count={severityCounts.high} />
            <SeverityBadge level="Medium" count={severityCounts.moderate} />
            <SeverityBadge level="Low" count={severityCounts.low} />
          </div>
          <p className="mt-2 text-xs text-muted-foreground">{totalFindings} total findings</p>
        </div>
      </div>

      <div className="glass-card rounded-xl p-6">
        <h2 className="font-display text-lg font-semibold mb-3">Status Timeline</h2>
        <div className="grid gap-3 md:grid-cols-3 text-sm">
          <div>
            <p className="text-xs text-muted-foreground">Queued</p>
            <p className="font-medium">{scan.created_at?.slice(0, 19) || "N/A"}</p>
          </div>
          <div>
            <p className="text-xs text-muted-foreground">Running</p>
            <p className="font-medium">{scan.started_at || "Not started"}</p>
          </div>
          <div>
            <p className="text-xs text-muted-foreground">{scan.status === "failed" ? "Failed" : "Completed"}</p>
            <p className="font-medium">{scan.completed_at || "Not completed"}</p>
          </div>
        </div>
        {scan.failure_reason && (
          <p className="mt-3 text-xs text-destructive">Failure reason: {scan.failure_reason}</p>
        )}
      </div>

      <div className="glass-card rounded-xl p-6">
        <h2 className="font-display text-lg font-semibold mb-2">Findings</h2>
        {codeFindings.length === 0 && networkFindings.length === 0 ? (
          <p className="text-sm text-muted-foreground">No findings recorded for this scan.</p>
        ) : (
          <div className="space-y-4">
            {codeFindings.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold mb-2">Code Findings</h3>
                <div className="space-y-2">
                  {codeFindings.map((finding) => (
                    <div key={finding.id} className="rounded-lg border border-border/60 p-3">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-sm font-medium">{finding.title}</p>
                        <SeverityBadge level={finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1)} count={1} />
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">{finding.description}</p>
                      {finding.file_path && (
                        <p className="text-xs text-muted-foreground mt-1">File: {finding.file_path}{finding.line_number ? `:${finding.line_number}` : ""}</p>
                      )}
                      {finding.remediation && <p className="text-xs text-muted-foreground mt-1">Remediation: {finding.remediation}</p>}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {networkFindings.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold mb-2">Network Findings</h3>
                <div className="space-y-2">
                  {networkFindings.map((finding) => (
                    <div key={finding.id} className="rounded-lg border border-border/60 p-3">
                      <div className="flex items-center justify-between gap-2">
                        <p className="text-sm font-medium">{finding.summary}</p>
                        <SeverityBadge level={finding.severity.charAt(0).toUpperCase() + finding.severity.slice(1)} count={1} />
                      </div>
                      {finding.rationale && <p className="text-xs text-muted-foreground mt-1">{finding.rationale}</p>}
                      {finding.recommendation && <p className="text-xs text-muted-foreground mt-1">Recommendation: {finding.recommendation}</p>}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="glass-card rounded-xl p-6">
        <h2 className="font-display text-lg font-semibold mb-2">Linked Reports</h2>
        {reports.length === 0 ? (
          <p className="text-sm text-muted-foreground">No reports generated for this scan yet.</p>
        ) : (
          <div className="space-y-2">
            {reports.map((report) => (
              <div key={report.id} className="flex items-center justify-between gap-2 rounded-lg border border-border/60 p-3">
                <div>
                  <p className="text-sm font-medium">{report.scope} report</p>
                  <p className="text-xs text-muted-foreground">Generated: {report.generated_at}</p>
                </div>
                <Button size="sm" variant="outline" onClick={() => handleDownload(report)}>
                  Download
                </Button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
