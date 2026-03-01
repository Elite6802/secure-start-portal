import { useEffect, useMemo, useState } from "react";
import { Shield, Activity, FileText, AlertTriangle, Server, Scan, Info, Code2, GitBranch, ClipboardCheck } from "lucide-react";
import { Area, AreaChart, Bar, BarChart, Cell, Pie, PieChart, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { Link, useOutletContext } from "react-router-dom";
import { ServiceRequestCard } from "@/components/dashboard/ServiceRequestCard";
import { Tooltip as Hint, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { PaginatedResponse, apiRequest, unwrapResults } from "@/lib/api";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { Asset, CloudAccount, CloudFinding, CodeFinding, CodeRepository, Incident, Report, Scan as ScanType, ScanJob, SecurityStatus, ServiceRequest } from "@/lib/types";

type TooltipPayloadEntry = { dataKey?: string; name?: string; value?: number | string; color?: string };
type CustomTooltipProps = { active?: boolean; payload?: TooltipPayloadEntry[]; label?: string | number };

const CustomTooltip = ({ active, payload, label }: CustomTooltipProps) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-border bg-card px-3 py-2 text-xs shadow-lg">
      <p className="font-medium text-foreground mb-1">{label}</p>
      {payload.map((p) => (
        <p key={p.dataKey} style={{ color: p.color }} className="flex justify-between gap-4">
          <span className="text-muted-foreground">{p.name ?? p.dataKey}</span>
          <span className="font-semibold">{p.value}</span>
        </p>
      ))}
    </div>
  );
};

export default function DashboardHome() {
  const { role, accessRole } = useOutletContext<{ role: string; accessRole?: string | null }>();
  const isExecutiveView = role === "Executive";
  const isDeveloperView = role === "Developer";
  const isSecurityLeadView = role === "Security Lead";
  const dataRole = accessRole;
  const canAccessScans = dataRole === "Security Lead";
  const canAccessCode = dataRole === "Security Lead" || dataRole === "Developer";
  const canAccessIncidents = dataRole === "Security Lead" || dataRole === "Executive";
  const canAccessAssets = dataRole === "Security Lead";
  const canAccessScanJobs = dataRole === "Security Lead";
  const canAccessReports = dataRole === "Security Lead" || dataRole === "Executive";
  const [activeStat, setActiveStat] = useState<null | { key: string; label: string }>(null);
  const canAccessCloud = dataRole === "Security Lead";
  const [status, setStatus] = useState<SecurityStatus | null>(null);
  const [scans, setScans] = useState<ScanType[]>([]);
  const [repos, setRepos] = useState<CodeRepository[]>([]);
  const [findings, setFindings] = useState<CodeFinding[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [scanJobs, setScanJobs] = useState<ScanJob[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [cloudAccounts, setCloudAccounts] = useState<CloudAccount[]>([]);
  const [cloudFindings, setCloudFindings] = useState<CloudFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        setError(null);
        const statusData = await apiRequest<SecurityStatus>("/security-status/");
        setStatus(statusData);

        if (canAccessScans) {
          const scansData = await apiRequest<PaginatedResponse<ScanType>>("/scans/");
          setScans(unwrapResults<ScanType>(scansData));
        } else {
          setScans([]);
        }

        if (canAccessCode) {
          const [reposData, findingsData] = await Promise.all([
            apiRequest<PaginatedResponse<CodeRepository>>("/code-repositories/"),
            apiRequest<PaginatedResponse<CodeFinding>>("/code-findings/"),
          ]);
          setRepos(unwrapResults<CodeRepository>(reposData));
          setFindings(unwrapResults<CodeFinding>(findingsData));
        } else {
          setRepos([]);
          setFindings([]);
        }

        if (canAccessAssets && canAccessScanJobs && canAccessIncidents) {
          const [assetsData, scanJobsData, incidentsData] = await Promise.all([
            apiRequest<PaginatedResponse<Asset>>("/assets/"),
            apiRequest<PaginatedResponse<ScanJob>>("/scan-jobs/"),
            apiRequest<PaginatedResponse<Incident>>("/incidents/"),
          ]);
          setAssets(unwrapResults<Asset>(assetsData));
          setScanJobs(unwrapResults<ScanJob>(scanJobsData));
          setIncidents(unwrapResults<Incident>(incidentsData));
        } else if (canAccessIncidents) {
          const incidentsData = await apiRequest<PaginatedResponse<Incident>>("/incidents/");
          setIncidents(unwrapResults<Incident>(incidentsData));
          setAssets([]);
          setScanJobs([]);
        } else {
          setAssets([]);
          setScanJobs([]);
          setIncidents([]);
        }

        if (canAccessReports) {
          const reportData = await apiRequest<PaginatedResponse<Report>>("/reports/");
          setReports(unwrapResults<Report>(reportData));
        } else {
          setReports([]);
        }

        if (canAccessCloud) {
          const [cloudAccountData, cloudFindingData] = await Promise.all([
            apiRequest<PaginatedResponse<CloudAccount>>("/cloud-accounts/"),
            apiRequest<PaginatedResponse<CloudFinding>>("/cloud-findings/"),
          ]);
          setCloudAccounts(unwrapResults<CloudAccount>(cloudAccountData));
          setCloudFindings(unwrapResults<CloudFinding>(cloudFindingData));
        } else {
          setCloudAccounts([]);
          setCloudFindings([]);
        }
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Failed to load dashboard data.");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [canAccessScans, canAccessCode, canAccessAssets, canAccessScanJobs, canAccessIncidents, canAccessReports, canAccessCloud]);

  const roleMessaging: Record<string, { headline: string; subhead: string }> = {
    "Security Lead": {
      headline: "Operational posture across assets, scans, and active response.",
      subhead: "Track coverage, prioritize remediation, and validate control effectiveness.",
    },
    Developer: {
      headline: "Engineering-focused security posture with actionable findings.",
      subhead: "Prioritize code and dependency risks with clear remediation guidance.",
    },
    Executive: {
      headline: "Executive overview of exposure, progress, and risk governance.",
      subhead: "Track trends, incident volume, and compliance alignment at a glance.",
    },
  };

  const statusStyles: Record<string, { bg: string; text: string; ring: string }> = {
    Green: { bg: "bg-success/15", text: "text-success", ring: "ring-success/30" },
    Amber: { bg: "bg-warning/15", text: "text-warning", ring: "ring-warning/30" },
    Red: { bg: "bg-destructive/15", text: "text-destructive", ring: "ring-destructive/30" },
  };

  const severityDistribution = useMemo(() => {
    if (!status) return [];
    return [
      { name: "Critical Risk Findings", value: status.risk_summary.critical, fill: "hsl(var(--destructive))" },
      { name: "Moderate Risk Findings", value: status.risk_summary.moderate, fill: "hsl(var(--warning))" },
      { name: "Low Risk Findings", value: status.risk_summary.low, fill: "hsl(var(--primary))" },
    ];
  }, [status]);

  const securityScoreTrend = useMemo(() => {
    if (!status) return [];
    if (status.posture_trend?.length) return status.posture_trend;
    const month = new Date().toLocaleString("en-US", { month: "short" });
    return [{ month, score: status.security_score }];
  }, [status]);

  const scanHistory = useMemo(() => {
    if (!scans.length) return [];
    const buckets: Record<string, { infra: number; web: number; code: number; cloud: number }> = {};
    scans.forEach((scan) => {
      const dateStr = (scan.completed_at || scan.started_at || scan.created_at).slice(0, 10);
      if (!buckets[dateStr]) {
        buckets[dateStr] = { infra: 0, web: 0, code: 0, cloud: 0 };
      }
      if (scan.scan_type === "infrastructure") buckets[dateStr].infra += 1;
      if (scan.scan_type === "web" || scan.scan_type === "api") buckets[dateStr].web += 1;
      if (scan.scan_type === "code") buckets[dateStr].code += 1;
      if (scan.scan_type === "cloud") buckets[dateStr].cloud += 1;
    });
    return Object.entries(buckets)
      .sort(([a], [b]) => a.localeCompare(b))
      .slice(-6)
      .map(([date, counts]) => ({
        date: date.slice(5),
        ...counts,
      }));
  }, [scans]);

  const incidentSeveritySummary = useMemo(() => {
    const summary = { critical: 0, high: 0, moderate: 0, low: 0 };
    incidents.forEach((incident) => {
      if (incident.severity === "critical") summary.critical += 1;
      if (incident.severity === "high") summary.high += 1;
      if (incident.severity === "moderate") summary.moderate += 1;
      if (incident.severity === "low") summary.low += 1;
    });
    return summary;
  }, [incidents]);

  const codeFindingSummary = useMemo(() => {
    const summary = { critical: 0, high: 0, moderate: 0, low: 0, secrets: 0, dependency: 0, sast: 0 };
    findings.forEach((finding) => {
      if (finding.severity === "critical") summary.critical += 1;
      if (finding.severity === "high") summary.high += 1;
      if (finding.severity === "moderate") summary.moderate += 1;
      if (finding.severity === "low") summary.low += 1;
      if (finding.category === "secrets") summary.secrets += 1;
      if (finding.category === "dependency") summary.dependency += 1;
      if (finding.category === "sast") summary.sast += 1;
    });
    return summary;
  }, [findings]);

  const repoSummary = useMemo(() => {
    const summary: Record<string, { name: string; count: number }> = {};
    repos.forEach((repo) => {
      summary[repo.id] = { name: repo.repo_url, count: 0 };
    });
    findings.forEach((finding) => {
      if (!summary[finding.repository]) {
        summary[finding.repository] = { name: finding.repository, count: 0 };
      }
      summary[finding.repository].count += 1;
    });
    return Object.values(summary).sort((a, b) => b.count - a.count);
  }, [repos, findings]);

  const scanJobSummary = useMemo(() => {
    const summary = { queued: 0, running: 0, completed: 0, failed: 0 };
    scanJobs.forEach((job) => {
      if (job.status === "queued") summary.queued += 1;
      if (job.status === "running") summary.running += 1;
      if (job.status === "completed") summary.completed += 1;
      if (job.status === "failed") summary.failed += 1;
    });
    return summary;
  }, [scanJobs]);

  const latestReport = useMemo(() => {
    if (!reports.length) return null;
    return [...reports].sort((a, b) => (a.generated_at < b.generated_at ? 1 : -1))[0];
  }, [reports]);

  const topRepoRisk = useMemo(() => repoSummary.slice(0, 3), [repoSummary]);

  const activeQueue = useMemo(
    () => scanJobs.filter((job) => job.status === "queued" || job.status === "running").slice(0, 4),
    [scanJobs]
  );

  const complianceItems = useMemo(() => {
    const summary = status?.compliance_summary;
    return [
      { label: "OWASP Top 10", value: summary?.owasp_top_10 ?? "Not Assessed" },
      { label: "ISO 27001", value: summary?.iso_27001 ?? "Not Assessed" },
      { label: "NIST 800-53", value: summary?.nist_800_53 ?? "Not Assessed" },
    ];
  }, [status]);

  const trendLabel = useMemo(() => {
    if (!status) return "Stable";
    if (status.security_score >= 80) return "Improving";
    if (status.security_score >= 60) return "Stable";
    return "Worsening";
  }, [status]);

  const executiveStats = useMemo(() => {
    if (!status) return [];
    return [
      { key: "posture_index", label: "Security Posture Index", value: `${status.security_score}/100`, icon: Shield, color: "text-primary" },
      { key: "risk_trend", label: "Risk Trend", value: trendLabel, icon: Activity, color: "text-muted-foreground" },
      { key: "open_incidents", label: "Open Incidents", value: status.open_incidents, icon: AlertTriangle, color: "text-warning" },
      { key: "compliance_posture", label: "Compliance Posture", value: `${complianceItems.filter((c) => c.value === "Covered").length}/3 Covered`, icon: ClipboardCheck, color: "text-success" },
    ];
  }, [status, trendLabel, complianceItems]);

  const developerStats = useMemo(() => {
    return [
      { key: "open_code_findings", label: "Open Code Findings", value: findings.length, icon: Code2, color: "text-primary" },
      { key: "secrets_detected", label: "Secrets Detected", value: codeFindingSummary.secrets, icon: AlertTriangle, color: "text-destructive" },
      { key: "dependency_risks", label: "Dependency Risks", value: codeFindingSummary.dependency, icon: FileText, color: "text-warning" },
      { key: "repos_impacted", label: "Repositories Impacted", value: repos.length, icon: GitBranch, color: "text-accent" },
    ];
  }, [findings.length, codeFindingSummary.secrets, codeFindingSummary.dependency, repos.length]);

  const developerCategoryBreakdown = useMemo(() => {
    return [
      { name: "Secrets", value: codeFindingSummary.secrets, fill: "hsl(var(--destructive))" },
      { name: "Dependencies", value: codeFindingSummary.dependency, fill: "hsl(var(--warning))" },
      { name: "SAST", value: codeFindingSummary.sast, fill: "hsl(var(--primary))" },
    ];
  }, [codeFindingSummary]);

  const leadStats = useMemo(() => {
    if (!status) return [];
    return [
      { key: "posture_index", label: "Security Posture Index", value: `${status.security_score}/100`, icon: Shield, color: "text-primary" },
      { key: "protected_assets", label: "Protected Assets", value: assets.length || status.assets_monitored, icon: Server, color: "text-accent" },
      { key: "scans_30d", label: "Automated Scans (30d)", value: status.scans_last_30_days, icon: Scan, color: "text-primary" },
      { key: "open_incidents", label: "Open Incidents", value: status.open_incidents, icon: AlertTriangle, color: "text-warning" },
      { key: "scan_jobs_in_progress", label: "Scan Jobs In Progress", value: scanJobSummary.queued + scanJobSummary.running, icon: Activity, color: "text-muted-foreground" },
      { key: "compliance_coverage", label: "Compliance Coverage", value: `${complianceItems.filter((c) => c.value === "Covered").length}/3 Covered`, icon: ClipboardCheck, color: "text-success" },
    ];
  }, [status, assets.length, scanJobSummary, complianceItems]);

  const cloudFindingSummary = useMemo(() => {
    const summary = { critical: 0, high: 0, moderate: 0, low: 0 };
    cloudFindings.forEach((finding) => {
      if (finding.severity === "critical") summary.critical += 1;
      if (finding.severity === "high") summary.high += 1;
      if (finding.severity === "moderate") summary.moderate += 1;
      if (finding.severity === "low") summary.low += 1;
    });
    return summary;
  }, [cloudFindings]);

  const cloudAccountStatus = useMemo(() => {
    const status = { active: 0, disabled: 0, error: 0 };
    cloudAccounts.forEach((account) => {
      if (account.status === "active") status.active += 1;
      if (account.status === "disabled") status.disabled += 1;
      if (account.status === "error") status.error += 1;
    });
    return status;
  }, [cloudAccounts]);

  const topFindings = useMemo(() => {
    const weight: Record<string, number> = { critical: 4, high: 3, moderate: 2, low: 1 };
    return [...findings]
      .sort((a, b) => (weight[b.severity] || 0) - (weight[a.severity] || 0))
      .slice(0, 5);
  }, [findings]);

  const recentIncidents = useMemo(() => {
    return [...incidents]
      .sort((a, b) => (b.detected_at || "").localeCompare(a.detected_at || ""))
      .slice(0, 5);
  }, [incidents]);

  const complianceTone: Record<string, string> = {
    Covered: "text-success",
    Partial: "text-warning",
    "Not Assessed": "text-muted-foreground",
  };
  const formatSeverity = (value: string) => (value === "moderate" ? "Moderate" : value.charAt(0).toUpperCase() + value.slice(1));
  const bannerStyle = status ? statusStyles[status.status_banner.status] ?? statusStyles.Amber : statusStyles.Amber;
  type ServiceType = ServiceRequest["service_type"];
  type TargetField = "repository_url" | "domain_url" | "ip_cidr" | "asset" | "cloud_account";
  type ServiceOption = { value: ServiceType; label: string; targetField?: TargetField; targetPlaceholder?: string };
  const baseCodeOptions: ServiceOption[] = [
    { value: "CODE_SECRETS_SCAN", label: "Code Secrets Scan", targetField: "repository_url", targetPlaceholder: "Repository URL" },
    { value: "DEPENDENCY_VULN_SCAN", label: "Dependency Vulnerability Scan", targetField: "repository_url", targetPlaceholder: "Repository URL" },
    { value: "CODE_COMPLIANCE_SCAN", label: "Code Standards Compliance (Full)", targetField: "repository_url", targetPlaceholder: "Repository URL" },
    { value: "CODE_COMPLIANCE_PYTHON", label: "Python PEP8 Compliance", targetField: "repository_url", targetPlaceholder: "Repository URL" },
    { value: "CODE_COMPLIANCE_HTML", label: "HTML Standards Compliance", targetField: "repository_url", targetPlaceholder: "Repository URL" },
    { value: "CODE_COMPLIANCE_CSS", label: "CSS Standards Compliance", targetField: "repository_url", targetPlaceholder: "Repository URL" },
    { value: "CODE_COMPLIANCE_JAVASCRIPT", label: "JavaScript Standards Compliance", targetField: "repository_url", targetPlaceholder: "Repository URL" },
    { value: "CODE_COMPLIANCE_REACT", label: "React Standards Compliance", targetField: "repository_url", targetPlaceholder: "Repository URL" },
  ];
  const requestOptions: ServiceOption[] = accessRole === "Security Lead"
    ? [
        ...baseCodeOptions,
        { value: "NETWORK_CONFIGURATION_SCAN", label: "Network Configuration Scan", targetField: "domain_url", targetPlaceholder: "Domain or IP/CIDR" },
        { value: "WEB_EXPOSURE_SCAN", label: "Web Exposure Scan", targetField: "domain_url", targetPlaceholder: "Target domain or URL" },
        { value: "API_SECURITY_SCAN", label: "API Security Scan", targetField: "domain_url", targetPlaceholder: "Target API base URL" },
        { value: "INFRASTRUCTURE_HARDENING_SCAN", label: "Infrastructure Hardening Scan", targetField: "domain_url", targetPlaceholder: "Domain or IP/CIDR" },
        { value: "CLOUD_POSTURE_SCAN", label: "Cloud Posture Scan", targetField: "cloud_account", targetPlaceholder: "Cloud account ID" },
      ]
    : baseCodeOptions;

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Security Posture Overview</h1>
      <p className="text-sm text-muted-foreground mb-2">{roleMessaging[role]?.headline}</p>
      <p className="text-xs text-muted-foreground mb-8">{roleMessaging[role]?.subhead}</p>

      <div className="mb-8 grid gap-4 lg:grid-cols-[1.2fr_1fr]">
        <div className="glass-card rounded-xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Role Focus</p>
              <p className="font-display text-lg font-semibold">{role}</p>
            </div>
            <div className="text-xs text-muted-foreground">
              Updated {new Date().toLocaleString()}
            </div>
          </div>
          <p className="mt-3 text-sm text-muted-foreground">
            Keep an eye on active exposure, remediation momentum, and any elevated-risk findings.
          </p>
        </div>
        <div className="glass-card rounded-xl p-5">
          <p className="text-xs uppercase tracking-wide text-muted-foreground mb-3">Quick Actions</p>
          <div className="flex flex-wrap gap-2">
            {(isSecurityLeadView || isDeveloperView) && (
              <Link to="/dashboard/scans" className="rounded-lg border border-border px-3 py-2 text-xs font-semibold hover:border-primary">
                View Active Scans
              </Link>
            )}
            {(isSecurityLeadView || isExecutiveView) && (
              <Link to="/dashboard/reports" className="rounded-lg border border-border px-3 py-2 text-xs font-semibold hover:border-primary">
                Open Reports
              </Link>
            )}
            {isDeveloperView && (
              <Link to="/dashboard/code-security" className="rounded-lg border border-border px-3 py-2 text-xs font-semibold hover:border-primary">
                Review Code Findings
              </Link>
            )}
          </div>
        </div>
      </div>

      <ServiceRequestCard
        title="Request Security Review"
        description="Request a focused security review for a specific scope. The platform team will validate access and return findings."
        serviceOptions={requestOptions}
        allowedRoles={["Security Lead", "Developer"]}
        accessRole={accessRole}
        helperText="Requests are reviewed by the platform security team."
        justificationPlaceholder="Summarize the scope, urgency, and business impact."
        cloudAccounts={cloudAccounts}
      />

      {loading && <p className="text-sm text-muted-foreground mb-6">Loading dashboard data...</p>}
      {error && <p className="text-sm text-destructive mb-6">{error}</p>}

      {status && (isExecutiveView || isSecurityLeadView) && (
        <div className={`mb-8 flex flex-col gap-3 rounded-xl border border-border/60 ${bannerStyle.bg} p-5 ring-1 ${bannerStyle.ring}`}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Global Security Status</span>
            <span className={`text-xs font-semibold ${bannerStyle.text}`}>{status.status_banner.status}</span>
          </div>
          <div>
            <p className="font-display text-lg font-semibold">{status.status_banner.headline}</p>
            <p className="text-sm text-muted-foreground">{status.status_banner.detail}</p>
          </div>
        </div>
      )}

      {isExecutiveView && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {executiveStats.map((s) => (
              <button
                key={s.label}
                type="button"
                onClick={() => setActiveStat({ key: s.key, label: s.label })}
                className="glass-card rounded-xl p-5 text-left transition hover:border-primary/30 focus:outline-none focus:ring-2 focus:ring-primary/30"
              >
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-medium text-muted-foreground">{s.label}</span>
                  <s.icon className={`h-4 w-4 ${s.color}`} />
                </div>
                <p className="font-display text-2xl font-bold">{s.value}</p>
                <p className="mt-2 text-[11px] text-muted-foreground">View details</p>
              </button>
            ))}
          </div>

          {latestReport && (
            <div className="mt-6 glass-card rounded-xl p-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <p className="text-xs uppercase tracking-wide text-muted-foreground">Latest Report</p>
                <p className="font-display text-lg font-semibold">Latest Report ({latestReport.scope})</p>
                <p className="text-xs text-muted-foreground">
                  Generated {new Date(latestReport.generated_at).toLocaleString()}
                </p>
              </div>
              <Link
                to="/dashboard/reports"
                className="rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground shadow-sm hover:opacity-90"
              >
                View Report
              </Link>
            </div>
          )}

          <div className="mt-6 glass-card rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-display text-lg font-semibold">Cloud Posture Summary</h2>
              <Hint>
                <TooltipTrigger asChild>
                  <button className="text-muted-foreground hover:text-foreground" aria-label="Cloud posture tooltip">
                    <Info className="h-4 w-4" />
                  </button>
                </TooltipTrigger>
                <TooltipContent className="max-w-xs text-xs">
                  Cloud findings are reported only for registered cloud accounts under your organization.
                </TooltipContent>
              </Hint>
            </div>
            {cloudAccounts.length === 0 ? (
              <p className="text-sm text-muted-foreground">No cloud accounts have been onboarded yet.</p>
            ) : (
              <div className="grid gap-4 md:grid-cols-2">
                <div className="rounded-lg border border-border/60 p-4">
                  <p className="text-xs text-muted-foreground">Accounts</p>
                  <p className="text-2xl font-bold font-display">{cloudAccounts.length}</p>
                  <div className="mt-2 text-xs text-muted-foreground flex flex-wrap gap-3">
                    <span>Active: {cloudAccountStatus.active}</span>
                    <span>Disabled: {cloudAccountStatus.disabled}</span>
                    <span className={cloudAccountStatus.error ? "text-destructive" : ""}>Errors: {cloudAccountStatus.error}</span>
                  </div>
                </div>
                <div className="rounded-lg border border-border/60 p-4">
                  <p className="text-xs text-muted-foreground">Cloud Findings</p>
                  <p className="text-2xl font-bold font-display">{cloudFindings.length}</p>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    <SeverityBadge level="Critical" count={cloudFindingSummary.critical} />
                    <SeverityBadge level="High" count={cloudFindingSummary.high} />
                    <SeverityBadge level="Medium" count={cloudFindingSummary.moderate} />
                    <SeverityBadge level="Low" count={cloudFindingSummary.low} />
                  </div>
                </div>
              </div>
            )}
            <div className="mt-4 flex flex-wrap gap-2">
              <Link to="/dashboard/scans" className="rounded-lg border border-border px-3 py-2 text-xs font-semibold hover:border-primary">
                Review Cloud Scans
              </Link>
              <Link to="/dashboard/reports" className="rounded-lg border border-border px-3 py-2 text-xs font-semibold hover:border-primary">
                View Cloud Reports
              </Link>
            </div>
          </div>

          <div className="mt-8 grid gap-6 lg:grid-cols-2">
            <div className="glass-card rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="font-display text-lg font-semibold">Posture Index Trend</h2>
                <Hint>
                  <TooltipTrigger asChild>
                    <button className="text-muted-foreground hover:text-foreground" aria-label="Posture index tooltip">
                      <Info className="h-4 w-4" />
                    </button>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs text-xs">
                    Trend reflects the combined impact of remediation progress and control maturity.
                  </TooltipContent>
                </Hint>
              </div>
              <ResponsiveContainer width="100%" height={240}>
                <AreaChart data={securityScoreTrend}>
                  <defs>
                    <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.3} />
                      <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="month" tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} axisLine={false} tickLine={false} />
                  <YAxis domain={[50, 100]} tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} axisLine={false} tickLine={false} />
                  <Tooltip content={<CustomTooltip />} />
                  <Area type="monotone" dataKey="score" stroke="hsl(var(--primary))" strokeWidth={2} fill="url(#scoreGradient)" name="Score" />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div className="glass-card rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="font-display text-lg font-semibold">Compliance Posture</h2>
                <Hint>
                  <TooltipTrigger asChild>
                    <button className="text-muted-foreground hover:text-foreground" aria-label="Compliance posture tooltip">
                      <Info className="h-4 w-4" />
                    </button>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs text-xs">
                    Summary reflects current coverage against key standards.
                  </TooltipContent>
                </Hint>
              </div>
              <div className="grid gap-3 sm:grid-cols-3">
                {complianceItems.map((item) => (
                  <div key={item.label} className="rounded-lg bg-secondary/40 p-4">
                    <p className="text-xs text-muted-foreground">{item.label}</p>
                    <p className={`text-sm font-semibold ${complianceTone[item.value] || "text-muted-foreground"}`}>{item.value}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="mt-6 glass-card rounded-xl p-6">
            <h2 className="font-display text-lg font-semibold mb-4">Open Incidents by Severity</h2>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <div className="rounded-lg bg-destructive/10 p-4 text-center">
                <p className="text-2xl font-bold text-destructive font-display">{incidentSeveritySummary.critical}</p>
                <p className="text-xs text-muted-foreground mt-1">Critical</p>
              </div>
              <div className="rounded-lg bg-destructive/10 p-4 text-center">
                <p className="text-2xl font-bold text-destructive font-display">{incidentSeveritySummary.high}</p>
                <p className="text-xs text-muted-foreground mt-1">High</p>
              </div>
              <div className="rounded-lg bg-warning/10 p-4 text-center">
                <p className="text-2xl font-bold text-warning font-display">{incidentSeveritySummary.moderate}</p>
                <p className="text-xs text-muted-foreground mt-1">Moderate</p>
              </div>
              <div className="rounded-lg bg-primary/10 p-4 text-center">
                <p className="text-2xl font-bold text-primary font-display">{incidentSeveritySummary.low}</p>
                <p className="text-xs text-muted-foreground mt-1">Low</p>
              </div>
            </div>
          </div>

          <div className="mt-6 grid gap-6 lg:grid-cols-2">
            <div className="glass-card rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="font-display text-lg font-semibold">Security Posture Trend</h2>
                <Hint>
                  <TooltipTrigger asChild>
                    <button className="text-muted-foreground hover:text-foreground" aria-label="Posture trend tooltip">
                      <Info className="h-4 w-4" />
                    </button>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs text-xs">
                    Trend shows how overall security posture is moving over time.
                  </TooltipContent>
                </Hint>
              </div>
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={securityScoreTrend}>
                  <defs>
                    <linearGradient id="execScoreGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.35} />
                      <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="month" tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} axisLine={false} tickLine={false} />
                  <YAxis domain={[50, 100]} tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} axisLine={false} tickLine={false} />
                  <Tooltip content={<CustomTooltip />} />
                  <Area type="monotone" dataKey="score" stroke="hsl(var(--primary))" strokeWidth={2} fill="url(#execScoreGradient)" name="Score" />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div className="glass-card rounded-xl p-6">
              <h2 className="font-display text-lg font-semibold mb-3">Executive Risk Summary</h2>
              <ul className="text-sm text-muted-foreground space-y-2">
                <li>Overall posture is {trendLabel.toLowerCase()} based on current controls and scan coverage.</li>
                <li>{incidentSeveritySummary.critical + incidentSeveritySummary.high} high-priority incidents remain open.</li>
                <li>{complianceItems.filter((c) => c.value === "Covered").length}/3 compliance frameworks fully covered.</li>
              </ul>
              <div className="mt-4 rounded-lg border border-border/60 bg-secondary/30 p-4">
                <p className="text-xs text-muted-foreground">Business impact</p>
                <p className="text-sm font-medium">{status?.status_banner.headline}</p>
                <p className="text-xs text-muted-foreground mt-1">{status?.status_banner.detail}</p>
              </div>
            </div>
          </div>
        </>
      )}

      {isDeveloperView && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {developerStats.map((s) => (
              <button
                key={s.label}
                type="button"
                onClick={() => setActiveStat({ key: s.key, label: s.label })}
                className="glass-card rounded-xl p-5 text-left transition hover:border-primary/30 focus:outline-none focus:ring-2 focus:ring-primary/30"
              >
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-medium text-muted-foreground">{s.label}</span>
                  <s.icon className={`h-4 w-4 ${s.color}`} />
                </div>
                <p className="font-display text-2xl font-bold">{s.value}</p>
                <p className="mt-2 text-[11px] text-muted-foreground">View details</p>
              </button>
            ))}
          </div>

          <div className="mt-6 grid gap-6 lg:grid-cols-2">
            <div className="glass-card rounded-xl p-6">
              <h2 className="font-display text-lg font-semibold mb-3">Next Best Actions</h2>
              <ul className="text-sm text-muted-foreground space-y-2">
                <li>Review the top findings and apply the highest severity fixes first.</li>
                <li>Lock dependency versions after updates to reduce regression risk.</li>
                <li>Re-run scans after fixes to confirm remediation.</li>
              </ul>
              <div className="mt-4 flex flex-wrap gap-2">
                <Link to="/dashboard/code-security" className="rounded-lg border border-border px-3 py-2 text-xs font-semibold hover:border-primary">
                  Open Code Findings
                </Link>
                <Link to="/dashboard/scans" className="rounded-lg border border-border px-3 py-2 text-xs font-semibold hover:border-primary">
                  View Scan History
                </Link>
              </div>
            </div>
            <div className="glass-card rounded-xl p-6">
              <h2 className="font-display text-lg font-semibold mb-3">Highest-Risk Repositories</h2>
              {topRepoRisk.length === 0 ? (
                <p className="text-sm text-muted-foreground">No repositories reporting findings yet.</p>
              ) : (
                <div className="space-y-3">
                  {topRepoRisk.map((repo) => (
                    <div key={repo.name} className="flex items-center justify-between rounded-lg border border-border/60 px-4 py-3">
                      <div className="flex items-center gap-2 text-sm">
                        <GitBranch className="h-4 w-4 text-primary" />
                        <span>{repo.name}</span>
                      </div>
                      <span className="text-xs text-muted-foreground">{repo.count} findings</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="mt-8 grid gap-6 lg:grid-cols-2">
            <div className="glass-card rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="font-display text-lg font-semibold">Top Findings</h2>
                <Hint>
                  <TooltipTrigger asChild>
                    <button className="text-muted-foreground hover:text-foreground" aria-label="Top findings tooltip">
                      <Info className="h-4 w-4" />
                    </button>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs text-xs">
                    Focus on the highest severity findings first to reduce exposure quickly.
                  </TooltipContent>
                </Hint>
              </div>
              {topFindings.length === 0 ? (
                <p className="text-sm text-muted-foreground">No code findings detected yet.</p>
              ) : (
                <div className="space-y-3">
                  {topFindings.map((finding) => (
                    <div key={finding.id} className="rounded-lg border border-border/60 p-4">
                      <div className="flex items-center justify-between mb-2">
                        <p className="font-medium text-sm">{finding.title}</p>
                        <SeverityBadge level={formatSeverity(finding.severity)} />
                      </div>
                      <p className="text-xs text-muted-foreground">{finding.description}</p>
                      <p className="text-xs text-muted-foreground mt-2">Remediation: {finding.remediation || "Review secure coding guidance."}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="glass-card rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="font-display text-lg font-semibold">Affected Repositories</h2>
                <Hint>
                  <TooltipTrigger asChild>
                    <button className="text-muted-foreground hover:text-foreground" aria-label="Repositories tooltip">
                      <Info className="h-4 w-4" />
                    </button>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs text-xs">
                    Repositories with findings are listed with the current count of open issues.
                  </TooltipContent>
                </Hint>
              </div>
              {repoSummary.length === 0 ? (
                <p className="text-sm text-muted-foreground">No repositories reporting findings yet.</p>
              ) : (
                <div className="space-y-3">
                  {repoSummary.slice(0, 6).map((repo) => (
                    <div key={repo.name} className="flex items-center justify-between rounded-lg border border-border/60 px-4 py-3">
                      <div className="flex items-center gap-2 text-sm">
                        <GitBranch className="h-4 w-4 text-primary" />
                        <span>{repo.name}</span>
                      </div>
                      <span className="text-xs text-muted-foreground">{repo.count} findings</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="glass-card rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="font-display text-lg font-semibold">Finding Category Breakdown</h2>
                <Hint>
                  <TooltipTrigger asChild>
                    <button className="text-muted-foreground hover:text-foreground" aria-label="Finding breakdown tooltip">
                      <Info className="h-4 w-4" />
                    </button>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs text-xs">
                    Distribution of code findings by detection category.
                  </TooltipContent>
                </Hint>
              </div>
              {findings.length === 0 ? (
                <p className="text-sm text-muted-foreground">No code findings recorded yet.</p>
              ) : (
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie data={developerCategoryBreakdown} cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={4} dataKey="value" nameKey="name" stroke="none">
                      {developerCategoryBreakdown.map((entry) => (
                        <Cell key={entry.name} fill={entry.fill} />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                    <Legend formatter={(value: string) => <span className="text-xs text-muted-foreground">{value}</span>} iconType="circle" iconSize={8} />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </div>
          </div>

          <div className="mt-6 glass-card rounded-xl p-6">
            <h2 className="font-display text-lg font-semibold mb-3">Remediation Guidance</h2>
            <ul className="text-sm text-muted-foreground list-disc list-inside space-y-2">
              <li>Rotate exposed secrets and invalidate any leaked credentials immediately.</li>
              <li>Patch vulnerable dependencies to the latest supported security releases.</li>
              <li>Close findings with documented remediation notes to support audit readiness.</li>
            </ul>
          </div>
        </>
      )}

      {isSecurityLeadView && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {leadStats.map((s) => (
              <button
                key={s.label}
                type="button"
                onClick={() => setActiveStat({ key: s.key, label: s.label })}
                className="glass-card rounded-xl p-5 text-left transition hover:border-primary/30 focus:outline-none focus:ring-2 focus:ring-primary/30"
              >
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-medium text-muted-foreground">{s.label}</span>
                  <s.icon className={`h-4 w-4 ${s.color}`} />
                </div>
                <p className="font-display text-2xl font-bold">{s.value}</p>
                <p className="mt-2 text-[11px] text-muted-foreground">View details</p>
              </button>
            ))}
          </div>

          {latestReport && (
            <div className="mt-6 glass-card rounded-xl p-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <p className="text-xs uppercase tracking-wide text-muted-foreground">Latest Report</p>
                <p className="font-display text-lg font-semibold">Latest Report ({latestReport.scope})</p>
                <p className="text-xs text-muted-foreground">
                  Generated {new Date(latestReport.generated_at).toLocaleString()}
                </p>
              </div>
              <Link
                to="/dashboard/reports"
                className="rounded-lg bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground shadow-sm hover:opacity-90"
              >
                View Report
              </Link>
            </div>
          )}

          <div className="mt-8 grid gap-6 lg:grid-cols-2">
            <div className="glass-card rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="font-display text-lg font-semibold">Posture Index Trend</h2>
                <Hint>
                  <TooltipTrigger asChild>
                    <button className="text-muted-foreground hover:text-foreground" aria-label="Posture index tooltip">
                      <Info className="h-4 w-4" />
                    </button>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs text-xs">
                    Trend reflects the combined impact of scan coverage, remediation progress, and control maturity.
                  </TooltipContent>
                </Hint>
              </div>
              <ResponsiveContainer width="100%" height={240}>
                <AreaChart data={securityScoreTrend}>
                  <defs>
                    <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.3} />
                      <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="month" tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} axisLine={false} tickLine={false} />
                  <YAxis domain={[50, 100]} tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} axisLine={false} tickLine={false} />
                  <Tooltip content={<CustomTooltip />} />
                  <Area type="monotone" dataKey="score" stroke="hsl(var(--primary))" strokeWidth={2} fill="url(#scoreGradient)" name="Score" />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div className="glass-card rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="font-display text-lg font-semibold">Finding Severity Distribution</h2>
                <Hint>
                  <TooltipTrigger asChild>
                    <button className="text-muted-foreground hover:text-foreground" aria-label="Severity distribution tooltip">
                      <Info className="h-4 w-4" />
                    </button>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs text-xs">
                    Severity summarizes validated findings across infrastructure, application, and code scans.
                  </TooltipContent>
                </Hint>
              </div>
              <ResponsiveContainer width="100%" height={240}>
                <PieChart>
                  <Pie data={severityDistribution} cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={4} dataKey="value" nameKey="name" stroke="none">
                    {severityDistribution.map((entry) => (
                      <Cell key={entry.name} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                  <Legend
                    formatter={(value: string) => <span className="text-xs text-muted-foreground">{value}</span>}
                    iconType="circle"
                    iconSize={8}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="mt-6 glass-card rounded-xl p-6">
            <h2 className="font-display text-lg font-semibold mb-4">Automated Scan Volume</h2>
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={scanHistory} barGap={2}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis dataKey="date" tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} axisLine={false} tickLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Legend
                  formatter={(value: string) => <span className="text-xs text-muted-foreground">{value}</span>}
                  iconType="circle"
                  iconSize={8}
                />
                <Bar dataKey="infra" name="Infrastructure" fill="hsl(var(--primary))" radius={[3, 3, 0, 0]} />
                <Bar dataKey="web" name="Web and API" fill="hsl(var(--accent))" radius={[3, 3, 0, 0]} />
                <Bar dataKey="code" name="Code and Dependencies" fill="hsl(var(--warning))" radius={[3, 3, 0, 0]} />
                <Bar dataKey="cloud" name="Cloud Posture" fill="hsl(var(--success))" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="mt-6 grid gap-6 lg:grid-cols-2">
            <div className="glass-card rounded-xl p-6">
              <h2 className="font-display text-lg font-semibold mb-4">Incident Timeline</h2>
              {recentIncidents.length === 0 ? (
                <p className="text-sm text-muted-foreground">No incidents recorded for this period.</p>
              ) : (
                <div className="space-y-3">
                  {recentIncidents.map((incident) => (
                    <div key={incident.id} className="rounded-lg border border-border/60 p-4">
                      <div className="flex items-center justify-between mb-1">
                        <p className="text-sm font-medium">{incident.description}</p>
                        <SeverityBadge level={formatSeverity(incident.severity)} />
                      </div>
                      <p className="text-xs text-muted-foreground">Status: {incident.status} • Detected {incident.detected_at?.slice(0, 10)}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="glass-card rounded-xl p-6">
              <h2 className="font-display text-lg font-semibold mb-4">Scan Job Status</h2>
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg bg-secondary/40 p-4 text-center">
                  <p className="text-2xl font-bold text-primary font-display">{scanJobSummary.queued}</p>
                  <p className="text-xs text-muted-foreground mt-1">Queued</p>
                </div>
                <div className="rounded-lg bg-secondary/40 p-4 text-center">
                  <p className="text-2xl font-bold text-warning font-display">{scanJobSummary.running}</p>
                  <p className="text-xs text-muted-foreground mt-1">Running</p>
                </div>
                <div className="rounded-lg bg-secondary/40 p-4 text-center">
                  <p className="text-2xl font-bold text-success font-display">{scanJobSummary.completed}</p>
                  <p className="text-xs text-muted-foreground mt-1">Completed</p>
                </div>
                <div className="rounded-lg bg-secondary/40 p-4 text-center">
                  <p className="text-2xl font-bold text-destructive font-display">{scanJobSummary.failed}</p>
                  <p className="text-xs text-muted-foreground mt-1">Failed</p>
                </div>
              </div>
              <div className="mt-4 rounded-lg border border-border/60 bg-secondary/20 p-4">
                <p className="text-xs uppercase tracking-wide text-muted-foreground mb-3">Active Queue</p>
                {activeQueue.length === 0 ? (
                  <p className="text-xs text-muted-foreground">No queued or running scan jobs right now.</p>
                ) : (
                  <div className="space-y-2">
                    {activeQueue.map((job) => (
                      <div key={job.id} className="flex items-center justify-between text-xs">
                        <div className="flex items-center gap-2">
                          <span className="inline-flex h-2 w-2 rounded-full bg-primary" />
                          <span className="font-medium">{job.scan_type.replace(/_/g, " ").toLowerCase()}</span>
                        </div>
                        <span className="text-muted-foreground">
                          {job.status} • {new Date(job.created_at).toLocaleDateString()}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>

          {status && (
            <div className="mt-6 glass-card rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="font-display text-lg font-semibold">Risk Findings Summary</h2>
                <Hint>
                  <TooltipTrigger asChild>
                    <button className="text-muted-foreground hover:text-foreground" aria-label="Risk summary tooltip">
                      <Info className="h-4 w-4" />
                    </button>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs text-xs">
                    Counts represent validated findings after triage, mapped to business impact.
                  </TooltipContent>
                </Hint>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <div className="rounded-lg bg-destructive/10 p-4 text-center">
                  <p className="text-3xl font-bold text-destructive font-display">{status.risk_summary.critical}</p>
                  <p className="text-xs text-muted-foreground mt-1">Critical Risk Findings</p>
                </div>
                <div className="rounded-lg bg-warning/10 p-4 text-center">
                  <p className="text-3xl font-bold text-warning font-display">{status.risk_summary.moderate}</p>
                  <p className="text-xs text-muted-foreground mt-1">Moderate Risk Findings</p>
                </div>
                <div className="rounded-lg bg-primary/10 p-4 text-center">
                  <p className="text-3xl font-bold text-primary font-display">{status.risk_summary.low}</p>
                  <p className="text-xs text-muted-foreground mt-1">Low Risk Findings</p>
                </div>
              </div>
            </div>
          )}

          <div className="mt-6 glass-card rounded-xl p-6">
            <h2 className="font-display text-lg font-semibold mb-4">Compliance Mapping Overview</h2>
            <div className="grid gap-3 sm:grid-cols-3">
              {complianceItems.map((item) => (
                <div key={item.label} className="rounded-lg bg-secondary/40 p-4">
                  <p className="text-xs text-muted-foreground">{item.label}</p>
                  <p className={`text-sm font-semibold ${complianceTone[item.value] || "text-muted-foreground"}`}>{item.value}</p>
                </div>
              ))}
            </div>
          </div>
        </>
      )}

      <Dialog open={activeStat !== null} onOpenChange={(open) => (!open ? setActiveStat(null) : null)}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>{activeStat?.label ?? "Detail"}</DialogTitle>
            <DialogDescription>Context and supporting detail for this dashboard metric.</DialogDescription>
          </DialogHeader>

          <ScrollArea className="max-h-[70vh] pr-4">
            {!status && (
              <p className="text-sm text-muted-foreground">No status data loaded yet.</p>
            )}

            {activeStat?.key === "posture_index" && status && (
              <div className="space-y-4">
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-1">What This Measures</p>
                  <p className="text-sm text-muted-foreground">
                    Security Posture Index is a roll-up score based on scan results, open findings, and exposure indicators.
                    It is meant to guide prioritization and trend tracking, not to replace engineering review.
                  </p>
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="rounded-xl border border-border bg-background/60 p-4">
                    <p className="text-xs text-muted-foreground">Current Score</p>
                    <p className="mt-1 text-2xl font-semibold">{status.security_score}/100</p>
                  </div>
                  <div className="rounded-xl border border-border bg-background/60 p-4">
                    <p className="text-xs text-muted-foreground">Trend Label</p>
                    <p className="mt-1 text-2xl font-semibold">{trendLabel}</p>
                  </div>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-2">Where To Review</p>
                  <div className="flex flex-wrap gap-2">
                    <Button variant="outline" size="sm" asChild>
                      <Link to="/dashboard/analyst">Analyst Workspace</Link>
                    </Button>
                    <Button variant="outline" size="sm" asChild>
                      <Link to="/dashboard/reports">Reports</Link>
                    </Button>
                  </div>
                </div>
              </div>
            )}

            {activeStat?.key === "risk_trend" && status && (
              <div className="space-y-4">
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-1">What This Means</p>
                  <p className="text-sm text-muted-foreground">
                    Risk Trend is derived from posture history (when available) and the current score thresholds.
                  </p>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-xs text-muted-foreground">Current</p>
                  <p className="mt-1 text-2xl font-semibold">{trendLabel}</p>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-2">Where To Review</p>
                  <Button variant="outline" size="sm" asChild>
                    <Link to="/dashboard/analyst">Analyst Workspace</Link>
                  </Button>
                </div>
              </div>
            )}

            {activeStat?.key === "open_incidents" && status && (
              <div className="space-y-4">
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-1">What This Measures</p>
                  <p className="text-sm text-muted-foreground">
                    Open Incidents counts incident records that are not resolved. Use the incidents view for investigation and closure.
                  </p>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-xs text-muted-foreground">Open</p>
                  <p className="mt-1 text-2xl font-semibold">{status.open_incidents}</p>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-2">Where To Review</p>
                  <Button variant="outline" size="sm" asChild>
                    <Link to="/dashboard/incidents">Open Incidents</Link>
                  </Button>
                </div>
              </div>
            )}

            {(activeStat?.key === "compliance_posture" || activeStat?.key === "compliance_coverage") && (
              <div className="space-y-4">
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-1">What This Measures</p>
                  <p className="text-sm text-muted-foreground">
                    Compliance coverage is a read-only mapping derived from scan evidence and policy context. It’s an indicator of evidence availability, not a certification.
                  </p>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-2">Current Summary</p>
                  <div className="grid gap-2 sm:grid-cols-3">
                    {complianceItems.map((c) => (
                      <div key={c.label} className="rounded-lg border border-border/60 bg-card/40 p-3">
                        <p className="text-xs text-muted-foreground">{c.label}</p>
                        <p className="text-sm font-semibold">{c.value}</p>
                      </div>
                    ))}
                  </div>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-2">Where To Review</p>
                  <Button variant="outline" size="sm" asChild>
                    <Link to="/dashboard/compliance">Open Compliance Mapping</Link>
                  </Button>
                </div>
              </div>
            )}

            {activeStat?.key === "protected_assets" && (
              <div className="space-y-4">
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-1">What This Measures</p>
                  <p className="text-sm text-muted-foreground">
                    Protected Assets is the current inventory count in scope. Use the inventory page for asset-level details and risk ratings.
                  </p>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-xs text-muted-foreground">Assets</p>
                  <p className="mt-1 text-2xl font-semibold">{assets.length || status?.assets_monitored || 0}</p>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-2">Where To Review</p>
                  <Button variant="outline" size="sm" asChild>
                    <Link to="/dashboard/assets">Open Inventory</Link>
                  </Button>
                </div>
              </div>
            )}

            {activeStat?.key === "scans_30d" && status && (
              <div className="space-y-4">
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-1">What This Measures</p>
                  <p className="text-sm text-muted-foreground">
                    Automated Scans (30d) is the number of scan executions recorded in the last 30 days for this tenant.
                  </p>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-xs text-muted-foreground">Count (30d)</p>
                  <p className="mt-1 text-2xl font-semibold">{status.scans_last_30_days}</p>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-2">Where To Review</p>
                  <Button variant="outline" size="sm" asChild>
                    <Link to="/dashboard/scans">Open Scans</Link>
                  </Button>
                </div>
              </div>
            )}

            {activeStat?.key === "scan_jobs_in_progress" && (
              <div className="space-y-4">
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-1">What This Measures</p>
                  <p className="text-sm text-muted-foreground">
                    Scan Jobs In Progress is the current queued + running job count. Use scans for job-level progress and outputs.
                  </p>
                </div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="rounded-xl border border-border bg-background/60 p-4">
                    <p className="text-xs text-muted-foreground">Queued</p>
                    <p className="mt-1 text-2xl font-semibold">{scanJobSummary.queued}</p>
                  </div>
                  <div className="rounded-xl border border-border bg-background/60 p-4">
                    <p className="text-xs text-muted-foreground">Running</p>
                    <p className="mt-1 text-2xl font-semibold">{scanJobSummary.running}</p>
                  </div>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-2">Where To Review</p>
                  <Button variant="outline" size="sm" asChild>
                    <Link to="/dashboard/scans">Open Scans</Link>
                  </Button>
                </div>
              </div>
            )}

            {activeStat?.key === "open_code_findings" && (
              <div className="space-y-4">
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-1">What This Measures</p>
                  <p className="text-sm text-muted-foreground">
                    Open Code Findings counts the current code findings in scope for your organization’s scanned repositories.
                  </p>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-xs text-muted-foreground">Count</p>
                  <p className="mt-1 text-2xl font-semibold">{findings.length}</p>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-2">Where To Review</p>
                  <Button variant="outline" size="sm" asChild>
                    <Link to="/dashboard/code-security">Open Code Security</Link>
                  </Button>
                </div>
              </div>
            )}

            {activeStat?.key === "secrets_detected" && (
              <div className="space-y-4">
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-1">What This Measures</p>
                  <p className="text-sm text-muted-foreground">
                    Secrets Detected counts findings categorized as secrets (keys/tokens/credentials) in scanned repositories.
                  </p>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-xs text-muted-foreground">Count</p>
                  <p className="mt-1 text-2xl font-semibold">{codeFindingSummary.secrets}</p>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-2">Where To Review</p>
                  <Button variant="outline" size="sm" asChild>
                    <Link to="/dashboard/code-security">Open Code Security</Link>
                  </Button>
                </div>
              </div>
            )}

            {activeStat?.key === "dependency_risks" && (
              <div className="space-y-4">
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-1">What This Measures</p>
                  <p className="text-sm text-muted-foreground">
                    Dependency Risks counts dependency vulnerability findings (CVE-style) detected in scanned repositories.
                  </p>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-xs text-muted-foreground">Count</p>
                  <p className="mt-1 text-2xl font-semibold">{codeFindingSummary.dependency}</p>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-2">Where To Review</p>
                  <Button variant="outline" size="sm" asChild>
                    <Link to="/dashboard/code-security">Open Code Security</Link>
                  </Button>
                </div>
              </div>
            )}

            {activeStat?.key === "repos_impacted" && (
              <div className="space-y-4">
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-1">What This Measures</p>
                  <p className="text-sm text-muted-foreground">
                    Repositories Impacted counts repositories currently in scope for findings and scan history.
                  </p>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-xs text-muted-foreground">Repositories</p>
                  <p className="mt-1 text-2xl font-semibold">{repos.length}</p>
                </div>
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-2">Where To Review</p>
                  <Button variant="outline" size="sm" asChild>
                    <Link to="/dashboard/code-security">Open Code Security</Link>
                  </Button>
                </div>
              </div>
            )}
          </ScrollArea>
        </DialogContent>
      </Dialog>
    </div>
  );
}

