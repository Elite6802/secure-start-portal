import { useEffect, useMemo, useState } from "react";
import { useLocation, useOutletContext } from "react-router-dom";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { RoleRestricted } from "@/components/dashboard/RoleRestricted";
import { ServiceRequestCard } from "@/components/dashboard/ServiceRequestCard";
import { FileText, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { PaginatedResponse, apiRequest, downloadFile, unwrapResults } from "@/lib/api";
import { CodeFinding, NetworkFinding, Report } from "@/lib/types";
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

const severityFromFindings = (code: CodeFinding[], network: NetworkFinding[]): SeverityCounts => {
  const counts = emptyCounts();
  const tally = (severity?: string | null) => {
    if (!severity) return;
    const key = severity.toLowerCase() as keyof SeverityCounts;
    if (key in counts) {
      counts[key] += 1;
    }
  };
  code.forEach((finding) => tally(finding.severity));
  network.forEach((finding) => tally(finding.severity));
  return counts;
};

const cloudAccountLabel = (report: Report) => {
  if (report.scope !== "cloud") return null;
  if (!report.metadata || typeof report.metadata !== "object") return null;
  const metadata = report.metadata as Record<string, unknown>;
  const name = metadata.cloud_account_name as string | undefined;
  const provider = metadata.cloud_provider as string | undefined;
  if (!name && !provider) return null;
  return `${name || "Cloud account"}${provider ? ` (${String(provider).toUpperCase()})` : ""}`;
};

export default function Reports() {
  const { accessRole } = useOutletContext<{ role: string; accessRole?: string | null }>();
  const location = useLocation();
  const restricted = accessRole ? !["Security Lead", "Executive"].includes(accessRole) : true;
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [serviceFilter, setServiceFilter] = useState<string>("all");
  const [expandedReportId, setExpandedReportId] = useState<string | null>(null);
  const [details, setDetails] = useState<Record<string, { loading: boolean; error?: string; code: CodeFinding[]; network: NetworkFinding[] }>>({});

  const highlightReportId = (location.state as { highlightReportId?: string } | null)?.highlightReportId;

  useEffect(() => {
    const load = async () => {
      try {
        if (!accessRole || restricted) {
          setLoading(false);
          setError(null);
          return;
        }
        setLoading(true);
        const data = await apiRequest<PaginatedResponse<Report>>("/reports/");
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
    load();
  }, [accessRole, restricted]);

  useEffect(() => {
    if (highlightReportId) {
      setExpandedReportId(highlightReportId);
    }
  }, [highlightReportId]);

  const handleDownload = async (report: Report) => {
    try {
      await downloadFile(`/reports/${report.id}/download/`, `aegis-report-${report.id}.pdf`);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to download report.";
      toast({
        title: "Download failed",
        description: message,
        variant: "destructive",
      });
    }
  };

  const loadDetails = async (report: Report) => {
    if (accessRole !== "Security Lead") {
      return;
    }
    const key = report.id;
    setDetails((prev) => ({
      ...prev,
      [key]: { loading: true, code: prev[key]?.code || [], network: prev[key]?.network || [] },
    }));
    try {
      const params = report.service_request
        ? `service_request=${report.service_request}`
        : report.scan_job
        ? `scan_job=${report.scan_job}`
        : "";
      if (!params) {
        setDetails((prev) => ({ ...prev, [key]: { loading: false, code: [], network: [] } }));
        return;
      }
      const [codeData, networkData] = await Promise.all([
        apiRequest<PaginatedResponse<CodeFinding>>(`/code-findings/?${params}`),
        apiRequest<PaginatedResponse<NetworkFinding>>(`/network-findings/?${params}`),
      ]);
      setDetails((prev) => ({
        ...prev,
        [key]: {
          loading: false,
          code: unwrapResults<CodeFinding>(codeData),
          network: unwrapResults<NetworkFinding>(networkData),
        },
      }));
    } catch (err: unknown) {
      setDetails((prev) => ({
        ...prev,
        [key]: { loading: false, error: err instanceof Error ? err.message : "Failed to load findings.", code: [], network: [] },
      }));
    }
  };

  const handleResolve = async (finding: CodeFinding | NetworkFinding, type: "code" | "network", reportId: string) => {
    try {
      const endpoint = type === "code" ? `/code-findings/${finding.id}/resolve/` : `/network-findings/${finding.id}/resolve/`;
      await apiRequest(endpoint, { method: "POST" });
      setDetails((prev) => {
        const current = prev[reportId];
        if (!current) return prev;
        if (type === "code") {
          const updated = current.code.map((item) => (item.id === finding.id ? { ...item, status: "resolved" as const } : item)) as CodeFinding[];
          return { ...prev, [reportId]: { ...current, code: updated } };
        }
        const updated = current.network.map((item) => (item.id === finding.id ? { ...item, status: "resolved" as const } : item)) as NetworkFinding[];
        return { ...prev, [reportId]: { ...current, network: updated } };
      });
      toast({
        title: "Marked resolved",
        description: "The finding has been marked as resolved.",
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to resolve finding.";
      toast({
        title: "Update failed",
        description: message,
        variant: "destructive",
      });
    }
  };

  const aiGuidanceForCode = (finding: CodeFinding) => {
    if (finding.category === "dependency") {
      return [
        "Upgrade to a patched version and lock the dependency tree.",
        "Regenerate lock files and run unit tests for regression coverage.",
        "Validate production deployment against staging with security checks enabled.",
      ];
    }
    if (finding.category === "secrets") {
      return [
        "Immediately revoke the exposed credential and rotate keys.",
        "Remove the secret from source history and introduce a secret manager.",
        "Add pre-commit secret scanning to block future exposure.",
      ];
    }
    return [
      "Review the affected code paths and add targeted security checks.",
      "Document remediation steps and schedule validation scans.",
    ];
  };

  const aiGuidanceForNetwork = (finding: NetworkFinding) => {
    if (finding.finding_type === "exposed_service") {
      return [
        "Restrict access at the firewall to approved management IP ranges.",
        "Enforce MFA or VPN access for administrative services.",
        "Move admin interfaces behind a bastion host or private subnet.",
      ];
    }
    if (finding.finding_type === "misconfiguration") {
      return [
        "Disable legacy protocols and enforce secure defaults (TLS 1.2+).",
        "Harden security headers and verify baseline configuration.",
      ];
    }
    return [
      "Introduce segmentation to reduce east-west exposure.",
      "Review route tables and enforce least-privilege access paths.",
    ];
  };

  const filteredReports = useMemo(() => {
    if (serviceFilter === "all") return reports;
    return reports.filter((report) => report.service_request_type === serviceFilter);
  }, [reports, serviceFilter]);

  const latestReport = useMemo(() => {
    if (!reports.length) return null;
    return reports[0];
  }, [reports]);

  const latestSummaryCounts = useMemo(() => {
    if (!latestReport) return null;
    return (
      severityFromMetadata(latestReport.metadata) ||
      parseSeveritySummary(latestReport.summary) ||
      emptyCounts()
    );
  }, [latestReport]);

  const coverageConfidence = useMemo(() => {
    if (!latestSummaryCounts) return null;
    const riskScore =
      latestSummaryCounts.critical * 15 +
      latestSummaryCounts.high * 8 +
      latestSummaryCounts.moderate * 4 +
      latestSummaryCounts.low * 2;
    const score = Math.max(0, 100 - Math.min(100, riskScore));
    return score;
  }, [latestSummaryCounts]);

  const recommendationsFor = (codeFindings: CodeFinding[], networkFindings: NetworkFinding[]) => {
    const actions = [
      ...codeFindings.map((finding) => finding.remediation).filter(Boolean),
      ...networkFindings.map((finding) => finding.recommendation).filter(Boolean),
    ];
    const unique = Array.from(new Set(actions));
    return unique.slice(0, 6);
  };

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Security Reports</h1>
      <p className="text-sm text-muted-foreground mb-8">Executive-ready assessments summarizing findings, risk trends, and remediation progress.</p>

      <ServiceRequestCard
        title="Request Executive Report"
        description="Submit a report request for a specific scope. The platform team will validate data sources and publish the report."
        serviceType="DEPENDENCY_VULN_SCAN"
        targetField="domain_url"
        allowedRoles={["Security Lead"]}
        accessRole={accessRole}
        helperText="Requests are reviewed by the platform security team."
        targetPlaceholder="Scope (application, environment, timeframe)"
        justificationPlaceholder="Describe the reporting scope, audience, and time period."
      />

      {!accessRole && <p className="text-sm text-muted-foreground mb-6">Loading access profile...</p>}
      {accessRole && restricted && (
        <RoleRestricted
          title="Security reports restricted"
          description="Reports are curated for Security Lead and Executive stakeholders."
        />
      )}
      {accessRole && !restricted && (
        <>
          {loading && <p className="text-sm text-muted-foreground mb-6">Loading reports...</p>}
          {error && <p className="text-sm text-destructive mb-6">{error}</p>}

          {latestReport && (
            <div className="mb-6 grid gap-4 lg:grid-cols-[1.6fr_1fr]">
              <div className="glass-card rounded-xl p-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <p className="text-xs uppercase tracking-wide text-muted-foreground">Latest Report</p>
                  <p className="font-display text-lg font-semibold">Latest Report ({latestReport.scope})</p>
                  <p className="text-xs text-muted-foreground">
                    Generated {new Date(latestReport.generated_at).toLocaleString()}
                  </p>
                </div>
                <Button size="sm" onClick={() => handleDownload(latestReport)}>
                  <Download className="h-4 w-4 mr-2" /> Download PDF
                </Button>
              </div>
              <div className="glass-card rounded-xl p-6">
                <p className="text-xs uppercase tracking-wide text-muted-foreground">Executive Confidence</p>
                <p className="font-display text-2xl font-semibold mt-2">
                  {coverageConfidence !== null ? `${coverageConfidence}%` : "—"}
                </p>
                <p className="text-xs text-muted-foreground mt-2">
                  Based on severity distribution from the most recent report.
                </p>
                {latestSummaryCounts && (
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    <SeverityBadge level="Critical" count={latestSummaryCounts.critical} />
                    <SeverityBadge level="High" count={latestSummaryCounts.high} />
                    <SeverityBadge level="Medium" count={latestSummaryCounts.moderate} />
                    <SeverityBadge level="Low" count={latestSummaryCounts.low} />
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="mb-4 flex flex-wrap items-center gap-2">
            <Button
              variant={serviceFilter === "all" ? "default" : "outline"}
              size="sm"
              onClick={() => setServiceFilter("all")}
            >
              All Services
            </Button>
            {[
              { value: "CODE_SECRETS_SCAN", label: "Code Secrets" },
              { value: "DEPENDENCY_VULN_SCAN", label: "Dependency Scan" },
              { value: "CODE_COMPLIANCE_SCAN", label: "Code Compliance" },
              { value: "NETWORK_CONFIGURATION_SCAN", label: "Network Scan" },
              { value: "WEB_EXPOSURE_SCAN", label: "Web Exposure" },
              { value: "API_SECURITY_SCAN", label: "API Security" },
              { value: "INFRASTRUCTURE_HARDENING_SCAN", label: "Infrastructure" },
              { value: "CLOUD_POSTURE_SCAN", label: "Cloud Posture" },
            ].map((option) => (
              <Button
                key={option.value}
                variant={serviceFilter === option.value ? "default" : "outline"}
                size="sm"
                onClick={() => setServiceFilter(option.value)}
              >
                {option.label}
              </Button>
            ))}
          </div>

          <div className="space-y-4">
            {!loading && filteredReports.length === 0 && (
              <div className="glass-card rounded-xl p-6 text-sm text-muted-foreground">
                No reports match the selected service filter. Try another scope or submit a new report request.
              </div>
            )}
            {filteredReports.map((report) => {
              const isExpanded = expandedReportId === report.id;
              const detail = details[report.id];
              const meta = report.metadata && typeof report.metadata === "object" ? (report.metadata as Record<string, unknown>) : {};
              const posture = (meta.posture && typeof meta.posture === "object" ? (meta.posture as Record<string, unknown>) : null) || null;
              const maturity = (meta.maturity && typeof meta.maturity === "object" ? (meta.maturity as Record<string, unknown>) : null) || null;
              const threatModel = (meta.threat_model && typeof meta.threat_model === "object" ? (meta.threat_model as Record<string, unknown>) : null) || null;
              const exploitChains = Array.isArray(meta.exploit_chains) ? (meta.exploit_chains as Record<string, unknown>[]) : [];
              const summaryCounts =
                severityFromMetadata(report.metadata) ||
                parseSeveritySummary(report.summary) ||
                (detail ? severityFromFindings(detail.code, detail.network) : emptyCounts());
              const evidenceItems = detail
                ? [
                    ...detail.code.map((finding) => ({
                      id: finding.id,
                      label: `${finding.title}`,
                    })),
                    ...detail.network.map((finding) => ({
                      id: finding.id,
                      label: `${finding.summary}`,
                    })),
                  ]
                : [];
              const serviceLabel = report.service_request_type
                ? {
                    CODE_SECRETS_SCAN: "Code Secrets Scan",
                    DEPENDENCY_VULN_SCAN: "Dependency Vulnerability Scan",
                    CODE_COMPLIANCE_SCAN: "Code Standards Compliance",
                    NETWORK_CONFIGURATION_SCAN: "Network Configuration Scan",
                    WEB_EXPOSURE_SCAN: "Web Exposure Scan",
                    API_SECURITY_SCAN: "API Security Scan",
                    INFRASTRUCTURE_HARDENING_SCAN: "Infrastructure Hardening Scan",
                    CLOUD_POSTURE_SCAN: "Cloud Posture Scan",
                  }[report.service_request_type] || report.service_request_type
                : null;

              return (
              <div key={report.id} className="glass-card rounded-xl p-6">
                <div className="mb-3 flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                  <div className="flex items-start gap-3">
                    <div className="rounded-lg bg-primary/10 p-2 mt-0.5">
                      <FileText className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <h3 className="font-display font-semibold text-sm">Security Report</h3>
                      <div className="mt-1 flex flex-wrap items-center gap-2">
                        <span className="text-xs text-muted-foreground">{report.generated_at}</span>
                        <Badge variant="outline" className="text-xs font-normal">{report.scope}</Badge>
                        {serviceLabel && <Badge variant="secondary" className="text-xs font-normal">{serviceLabel}</Badge>}
                        {cloudAccountLabel(report) && (
                          <Badge variant="outline" className="text-xs font-normal">
                            {cloudAccountLabel(report)}
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="flex flex-wrap items-center gap-2 lg:justify-end">
                    <Button variant="outline" size="sm" className="gap-1.5 text-xs" onClick={() => handleDownload(report)}>
                      <Download className="h-3.5 w-3.5" />
                      Export PDF
                    </Button>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => {
                        setExpandedReportId(isExpanded ? null : report.id);
                        if (!isExpanded && !details[report.id]) {
                          loadDetails(report);
                        }
                      }}
                    >
                      {isExpanded ? "Hide Details" : "View Details"}
                    </Button>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground mb-3">{report.summary}</p>
                <div className="flex flex-wrap gap-2">
                  <SeverityBadge level="Critical" count={summaryCounts.critical} />
                  <SeverityBadge level="High" count={summaryCounts.high} />
                  <SeverityBadge level="Medium" count={summaryCounts.moderate} />
                  <SeverityBadge level="Low" count={summaryCounts.low} />
                </div>
                {isExpanded && (
                  <div className="mt-4 space-y-4">
                    <div className="grid gap-3 lg:grid-cols-3">
                      <div className="rounded-lg border border-border/60 p-4">
                        <h4 className="text-sm font-semibold mb-2">Posture & Maturity</h4>
                        <p className="text-xs text-muted-foreground">
                          Posture score:{" "}
                          <span className="font-semibold text-foreground">
                            {typeof posture?.score === "number" ? `${posture.score}/100` : "n/a"}
                          </span>{" "}
                          {posture?.grade ? `(${String(posture.grade)})` : ""}
                        </p>
                        <p className="text-xs text-muted-foreground mt-1">
                          Maturity:{" "}
                          <span className="font-semibold text-foreground">
                            {maturity?.level ? String(maturity.level) : "n/a"}
                          </span>
                          {typeof maturity?.overall === "number" ? ` · Avg ${maturity.overall}/5` : ""}
                        </p>
                      </div>
                      <div className="rounded-lg border border-border/60 p-4">
                        <h4 className="text-sm font-semibold mb-2">Threat Model Snapshot</h4>
                        <p className="text-xs text-muted-foreground mb-2">Likely actors & top threats (heuristic).</p>
                        <ul className="text-xs text-muted-foreground space-y-1">
                          {Array.isArray(threatModel?.actors) ? (threatModel.actors as unknown[]).slice(0, 2).map((a, i) => (
                            <li key={`actor-${i}`}>- {String(a)}</li>
                          )) : <li>- n/a</li>}
                          {Array.isArray(threatModel?.top_threats) ? (threatModel.top_threats as unknown[]).slice(0, 2).map((t, i) => (
                            <li key={`threat-${i}`}>* {String(t)}</li>
                          )) : null}
                        </ul>
                      </div>
                      <div className="rounded-lg border border-border/60 p-4">
                        <h4 className="text-sm font-semibold mb-2">Exploit Chains</h4>
                        {exploitChains.length ? (
                          <>
                            <p className="text-xs font-medium text-foreground">{String(exploitChains[0]?.title || "Attack path")}</p>
                            <ul className="text-xs text-muted-foreground mt-2 space-y-1">
                              {Array.isArray(exploitChains[0]?.steps)
                                ? (exploitChains[0]?.steps as unknown[]).slice(0, 3).map((s, i) => <li key={`step-${i}`}>- {String(s)}</li>)
                                : null}
                            </ul>
                          </>
                        ) : (
                          <p className="text-xs text-muted-foreground">No chains synthesized for this scan.</p>
                        )}
                      </div>
                    </div>
                    {accessRole !== "Security Lead" ? (
                      <div className="rounded-lg border border-border/60 p-4 text-sm text-muted-foreground">
                        Detailed findings are available to Security Leads. Contact your security lead for remediation guidance.
                      </div>
                    ) : detail?.loading ? (
                      <div className="text-sm text-muted-foreground">Loading report details...</div>
                    ) : detail?.error ? (
                      <div className="text-sm text-destructive">{detail.error}</div>
                    ) : (
                      <>
                        {evidenceItems.length > 0 && (
                          <div className="rounded-lg border border-border/60 p-4">
                            <h4 className="text-sm font-semibold mb-2">Evidence artifacts</h4>
                            <div className="flex flex-wrap gap-2">
                              {evidenceItems.map((item) => (
                                <a
                                  key={item.id}
                                  href={`#finding-${item.id}`}
                                  className="rounded-full border border-border/60 px-3 py-1 text-xs text-primary hover:bg-primary/10"
                                >
                                  {item.label}
                                </a>
                              ))}
                            </div>
                          </div>
                        )}
                        <div className="rounded-lg border border-border/60 p-4">
                          <h4 className="text-sm font-semibold mb-2">Findings</h4>
                          {detail?.code.length === 0 && detail?.network.length === 0 ? (
                            <p className="text-sm text-muted-foreground">No detailed findings available.</p>
                          ) : (
                            <div className="space-y-3">
                              {detail?.code.map((finding) => (
                                <div
                                  key={finding.id}
                                  id={`finding-${finding.id}`}
                                  className="rounded-md bg-secondary/40 p-3 text-sm"
                                >
                                  <div className="flex flex-wrap items-start justify-between gap-2">
                                    <span className="font-medium">{finding.title}</span>
                                    <div className="flex items-center gap-2">
                                      <Badge variant="outline" className="text-xs">{finding.severity}</Badge>
                                      <Badge variant={finding.status === "resolved" ? "secondary" : "outline"} className="text-xs">
                                        {finding.status || "open"}
                                      </Badge>
                                    </div>
                                  </div>
                                  <p className="text-xs text-muted-foreground mt-1">{finding.description}</p>
                                  {finding.file_path && (
                                    <p className="text-xs text-muted-foreground mt-1">
                                      File: {finding.file_path}{finding.line_number ? `:${finding.line_number}` : ""}
                                    </p>
                                  )}
                                  {finding.secret_type && (
                                    <p className="text-xs text-muted-foreground mt-1">Secret type: {finding.secret_type}</p>
                                  )}
                                  {finding.masked_value && (
                                    <p className="text-xs text-muted-foreground mt-1">Masked value: {finding.masked_value}</p>
                                  )}
                                  {typeof finding.confidence_score === "number" && (
                                    <p className="text-xs text-muted-foreground mt-1">Confidence score: {finding.confidence_score}%</p>
                                  )}
                                  {finding.remediation && (
                                    <p className="text-xs text-muted-foreground mt-2">Remediation: {finding.remediation}</p>
                                  )}
                                  {finding.standard_mapping?.length > 0 && (
                                    <p className="text-xs text-muted-foreground mt-2">
                                      Compliance: {finding.standard_mapping.join(", ")}
                                    </p>
                                  )}
                                  <div className="mt-3 rounded-md border border-border/60 bg-background/40 p-3">
                                    <p className="text-xs font-semibold text-muted-foreground mb-2">AI-guided remediation</p>
                                    <ul className="list-disc pl-5 text-xs text-muted-foreground space-y-1">
                                      {aiGuidanceForCode(finding).map((step) => (
                                        <li key={step}>{step}</li>
                                      ))}
                                    </ul>
                                  </div>
                                  <div className="mt-3 flex gap-2">
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      onClick={() => handleResolve(finding, "code", report.id)}
                                      disabled={finding.status === "resolved"}
                                    >
                                      {finding.status === "resolved" ? "Resolved" : "Mark Resolved"}
                                    </Button>
                                  </div>
                                </div>
                              ))}
                              {detail?.network.map((finding) => {
                                const evidence = (finding.evidence || {}) as Record<string, unknown>;
                                const host = typeof evidence.host === "string" ? evidence.host : undefined;
                                const port = typeof evidence.port === "number" ? evidence.port : undefined;
                                const service = typeof evidence.service === "string" ? evidence.service : undefined;
                                const version = typeof evidence.version === "string" ? evidence.version : undefined;
                                const cve = typeof evidence.cve === "string" ? evidence.cve : undefined;
                                const protocol = typeof evidence.protocol === "string" ? evidence.protocol : undefined;
                                const path = typeof evidence.path === "string" ? evidence.path : undefined;
                                const environment = typeof evidence.environment === "string" ? evidence.environment : undefined;
                                const osGuess = typeof evidence.os_guess === "string" ? evidence.os_guess : undefined;
                                const confidence = typeof finding.confidence_score === "number" ? finding.confidence_score : undefined;

                                return (
                                  <div
                                    key={finding.id}
                                    id={`finding-${finding.id}`}
                                    className="rounded-md bg-secondary/40 p-3 text-sm"
                                  >
                                  <div className="flex flex-wrap items-start justify-between gap-2">
                                    <span className="font-medium">{finding.summary}</span>
                                    <div className="flex items-center gap-2">
                                      <Badge variant="outline" className="text-xs">{finding.severity}</Badge>
                                      <Badge variant={finding.status === "resolved" ? "secondary" : "outline"} className="text-xs">
                                        {finding.status || "open"}
                                      </Badge>
                                    </div>
                                  </div>
                                  {(host || port || service || version || cve || protocol) && (
                                    <div className="mt-2 text-xs text-muted-foreground space-y-1">
                                      {host && <p>Host: {host}</p>}
                                      {port !== undefined && <p>Port: {port}</p>}
                                      {service && <p>Service: {service}</p>}
                                      {version && <p>Version: {version}</p>}
                                      {protocol && <p>Protocol: {protocol}</p>}
                                      {path && <p>Path: {path}</p>}
                                      {environment && <p>Environment: {environment}</p>}
                                      {osGuess && <p>OS fingerprint: {osGuess}</p>}
                                      {cve && <p>CVE: {cve}</p>}
                                      {confidence !== undefined && <p>Confidence score: {confidence}%</p>}
                                    </div>
                                  )}
                                  {finding.recommendation && (
                                    <p className="text-xs text-muted-foreground mt-2">Recommendation: {finding.recommendation}</p>
                                  )}
                                  {finding.rationale && (
                                    <p className="text-xs text-muted-foreground mt-1">Rationale: {finding.rationale}</p>
                                  )}
                                  <div className="mt-3 rounded-md border border-border/60 bg-background/40 p-3">
                                    <p className="text-xs font-semibold text-muted-foreground mb-2">AI-guided remediation</p>
                                    <ul className="list-disc pl-5 text-xs text-muted-foreground space-y-1">
                                      {aiGuidanceForNetwork(finding).map((step) => (
                                        <li key={step}>{step}</li>
                                      ))}
                                    </ul>
                                  </div>
                                  <div className="mt-3 flex gap-2">
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      onClick={() => handleResolve(finding, "network", report.id)}
                                      disabled={finding.status === "resolved"}
                                    >
                                      {finding.status === "resolved" ? "Resolved" : "Mark Resolved"}
                                    </Button>
                                  </div>
                                </div>
                                );
                              })}
                            </div>
                          )}
                        </div>
                        <div className="rounded-lg border border-border/60 p-4">
                          <h4 className="text-sm font-semibold mb-2">Recommended Actions</h4>
                          {detail ? (
                            <ul className="list-disc pl-5 text-sm text-muted-foreground space-y-1">
                              {recommendationsFor(detail.code, detail.network).map((item) => (
                                <li key={item}>{item}</li>
                              ))}
                              {recommendationsFor(detail.code, detail.network).length === 0 && (
                                <li>No remediation steps available yet.</li>
                              )}
                            </ul>
                          ) : (
                            <p className="text-sm text-muted-foreground">No recommendations available.</p>
                          )}
                        </div>
                      </>
                    )}
                  </div>
                )}
              </div>
            )})}
          </div>
        </>
      )}
    </div>
  );
}
