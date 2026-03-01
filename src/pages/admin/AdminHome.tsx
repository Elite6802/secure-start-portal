import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { PaginatedResponse, apiRequest, downloadFile, unwrapResults } from "@/lib/api";
import { Organization, UserAccount, ScanJob, Incident, ActivityLogItem, ServiceRequest, Report } from "@/lib/types";
import {
  Building2,
  Users,
  ClipboardList,
  AlertTriangle,
  Activity,
  Inbox,
  FileText,
  ShieldCheck,
  CalendarClock,
  SlidersHorizontal,
  ScrollText,
  History,
  Archive,
} from "lucide-react";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

export default function AdminHome() {
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [users, setUsers] = useState<UserAccount[]>([]);
  const [scanJobs, setScanJobs] = useState<ScanJob[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [activity, setActivity] = useState<ActivityLogItem[]>([]);
  const [serviceRequests, setServiceRequests] = useState<ServiceRequest[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  type HygieneOverview = {
    generated_at: string;
    inventory: {
      organizations: Array<{
        organization_id: string;
        organization_name: string;
        score: number;
        configured: boolean;
        categories: Array<{
          key: string;
          label: string;
          present: number;
          expected: number;
          status: "ok" | "warn" | "miss" | "ignored";
        }>;
      }>;
    };
    stale_assets: {
      threshold_days: number;
      count: number;
      results: Array<{
        asset_id: string;
        organization_id: string;
        organization_name: string;
        name: string;
        asset_type: string;
        identifier: string;
        risk_level: string;
        last_scanned_at: string | null;
        age_days: number | null;
        has_active_schedule: boolean;
      }>;
    };
    policy_issues: {
      count: number;
      results: Array<{
        severity: "critical" | "warning" | "moderate";
        organization_id: string;
        organization_name: string;
        code: string;
        title: string;
        detail: string;
      }>;
    };
  };

  const [hygiene, setHygiene] = useState<HygieneOverview | null>(null);
  const [activeHygiene, setActiveHygiene] = useState<null | "inventory" | "stale" | "policy">(null);
  const [schedulingAssetId, setSchedulingAssetId] = useState<string | null>(null);

  type OpsOverview = {
    generated_at: string;
    window_hours: number;
    workers: { ok: boolean; online: number; details: Record<string, { ok: boolean }>; error?: string };
    scan_queue: {
      queued: number;
      running: number;
      failed_recent: number;
      completed_recent: number;
      oldest_queued_minutes: number | null;
      jobs: Array<{
        scan_job_id: string;
        organization_id: string;
        scan_type: string;
        status: string;
        created_at: string;
        started_at: string | null;
        completed_at: string | null;
        retries: number;
        failure_reason?: string;
      }>;
    };
    durations: {
      sample_size: number;
      p95_ms_overall: number | null;
      p95_ms_by_type: Record<string, number | null>;
    };
    failures: {
      top_reasons: Array<{ code: string; count: number; examples: string[] }>;
      recent_failed: Array<{ scan_job_id: string; scan_type: string; failure_reason: string }>;
    };
    budget: {
      by_scan_type: Array<{
        scan_type: string;
        sample_size: number;
        avg_ports_checked: number;
        avg_validation_requests_used: number;
        p95_validation_requests_used: number;
      }>;
    };
  };

  const [ops, setOps] = useState<OpsOverview | null>(null);
  const [activeOps, setActiveOps] = useState<null | "queue" | "failures" | "budget">(null);

  type SsrfAuditRow = {
    id: string;
    timestamp: string;
    organization_id: string;
    organization_name: string;
    service_request_id: string;
    scan_job_id: string;
    requester_email: string;
    approver_email: string;
    authorization_reference: string;
    attempts_count: number;
    attempts: Array<{ probe_url?: string; ssrf_target?: string; parameter?: string }>;
    truncated: boolean;
  };
  type SsrfAudit = { generated_at: string; count: number; results: SsrfAuditRow[] };

  type PolicyChangeRow = {
    id: string;
    timestamp: string;
    organization_id: string;
    organization_name: string;
    changed_by_email: string;
    diff: {
      changed_fields?: string[];
      field_changes?: Record<string, { before: unknown; after: unknown }>;
      allowlist_changes?: Record<string, { added?: string[]; removed?: string[]; truncated?: boolean }>;
      inventory_changes?: Array<{ key: string; before: number; after: number }>;
    };
  };
  type PolicyChanges = { generated_at: string; count: number; results: PolicyChangeRow[] };

  type EvidenceRow = {
    report_id: string;
    organization_id: string;
    organization_name: string;
    service_request_id: string;
    scan_job_id: string;
    generated_at: string;
    expires_at: string;
    status: "ok" | "expiring" | "expired";
    days_left: number;
    appendix_present: boolean;
    appendix_size_bytes: number;
    appendix_size_human: string;
    error?: string;
  };
  type EvidenceRetention = {
    generated_at: string;
    retention_days: number;
    expiring_soon_days: number;
    counts: { ok: number; expiring: number; expired: number; missing: number };
    results: EvidenceRow[];
  };

  const [ssrfAudit, setSsrfAudit] = useState<SsrfAudit | null>(null);
  const [policyChanges, setPolicyChanges] = useState<PolicyChanges | null>(null);
  const [evidence, setEvidence] = useState<EvidenceRetention | null>(null);
  const [activeGov, setActiveGov] = useState<null | "ssrf" | "policy" | "evidence">(null);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError(null);
      const results = await Promise.allSettled([
        apiRequest<PaginatedResponse<Organization>>("/internal/organizations/"),
        apiRequest<PaginatedResponse<UserAccount>>("/internal/users/"),
        apiRequest<PaginatedResponse<ScanJob>>("/internal/scan-jobs/"),
        apiRequest<PaginatedResponse<Incident>>("/internal/incidents/"),
        apiRequest<PaginatedResponse<ActivityLogItem>>("/internal/activity-log/"),
        apiRequest<PaginatedResponse<ServiceRequest>>("/internal/service-requests/"),
        apiRequest<PaginatedResponse<Report>>("/internal/reports/"),
        apiRequest<HygieneOverview>("/internal/hygiene/overview/"),
        apiRequest<OpsOverview>("/internal/ops/overview/"),
        apiRequest<SsrfAudit>("/internal/governance/ssrf-audit/?limit=50"),
        apiRequest<PolicyChanges>("/internal/governance/policy-changes/?limit=50"),
        apiRequest<EvidenceRetention>("/internal/governance/evidence-retention/?limit=20&cache=0"),
      ]);

      const [
        orgData,
        userData,
        jobData,
        incidentData,
        activityData,
        requestData,
        reportData,
        hygieneData,
        opsData,
        ssrfAuditData,
        policyChangeData,
        evidenceData,
      ] = results.map((result) => (result.status === "fulfilled" ? result.value : null));

      if (!orgData && !userData && !jobData) {
        setError("Unable to load internal metrics. Please check your session.");
      }

      setOrgs(unwrapResults<Organization>(orgData));
      setUsers(unwrapResults<UserAccount>(userData));
      setScanJobs(unwrapResults<ScanJob>(jobData));
      setIncidents(unwrapResults<Incident>(incidentData));
      setActivity(unwrapResults<ActivityLogItem>(activityData));
      setServiceRequests(unwrapResults<ServiceRequest>(requestData));
      setReports(unwrapResults<Report>(reportData));
      setHygiene(hygieneData as HygieneOverview | null);
      setOps(opsData as OpsOverview | null);
      setSsrfAudit(ssrfAuditData as SsrfAudit | null);
      setPolicyChanges(policyChangeData as PolicyChanges | null);
      setEvidence(evidenceData as EvidenceRetention | null);
      setLoading(false);
    };
    load();
  }, []);

  const scoreTone = (score: number) => {
    if (score >= 85) return { chip: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700", bar: "bg-emerald-500" };
    if (score >= 60) return { chip: "border-amber-500/30 bg-amber-500/10 text-amber-700", bar: "bg-amber-500" };
    return { chip: "border-rose-500/30 bg-rose-500/10 text-rose-700", bar: "bg-rose-500" };
  };

  const issueTone = (sev: string) => {
    if (sev === "critical") return "border-rose-500/30 bg-rose-500/10 text-rose-700";
    if (sev === "warning") return "border-amber-500/30 bg-amber-500/10 text-amber-700";
    return "border-sky-500/30 bg-sky-500/10 text-sky-700";
  };

  const scheduleAsset = async (assetId: string) => {
    setSchedulingAssetId(assetId);
    setError(null);
    try {
      await apiRequest("/internal/hygiene/schedule-asset/", {
        method: "POST",
        body: JSON.stringify({ asset_id: assetId }),
      });
      const refreshed = await apiRequest<HygieneOverview>("/internal/hygiene/overview/");
      setHygiene(refreshed);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to schedule scan.");
    } finally {
      setSchedulingAssetId(null);
    }
  };

  const cards = [
    { label: "Organizations", value: orgs.length, icon: Building2, href: "/admin/organizations" },
    { label: "Users", value: users.length, icon: Users, href: "/admin/users" },
    { label: "Scan Jobs", value: scanJobs.length, icon: ClipboardList, href: "/admin/scan-jobs" },
    { label: "Service Requests", value: serviceRequests.length, icon: Inbox, href: "/admin/service-requests" },
    { label: "Reports", value: reports.length, icon: FileText, href: "/admin/reports" },
    { label: "Incidents", value: incidents.length, icon: AlertTriangle, href: "/admin/incidents" },
    { label: "Activity Log", value: activity.length, icon: Activity, href: "/admin/activity-log" },
  ];

  const failedScans = scanJobs.filter((job) => job.status === "failed");
  const pendingRequests = serviceRequests.filter((request) => request.status === "PENDING");
  const approvedRequests = serviceRequests.filter((request) => request.status === "APPROVED");
  const runningRequests = serviceRequests.filter((request) => request.status === "RUNNING");
  const completedRequests = serviceRequests.filter((request) => request.status === "COMPLETED");
  const failedRequests = serviceRequests.filter((request) => request.status === "FAILED");
  const queuedJobs = scanJobs.filter((job) => job.status === "queued");
  const runningJobs = scanJobs.filter((job) => job.status === "running");

  const avgCompleteness =
    hygiene?.inventory?.organizations?.length
      ? Math.round(
          hygiene.inventory.organizations.reduce((acc, row) => acc + (row.score || 0), 0) / hygiene.inventory.organizations.length
        )
      : 0;
  const lowCompletenessCount = (hygiene?.inventory?.organizations || []).filter((o) => (o.score || 0) < 60).length;
  const staleCount = hygiene?.stale_assets?.count || 0;
  const issuesCount = hygiene?.policy_issues?.count || 0;

  const ssrfAuditCount = ssrfAudit?.count || 0;
  const policyChangeCount = policyChanges?.count || 0;
  const evidenceCounts = evidence?.counts || { ok: 0, expiring: 0, expired: 0, missing: 0 };
  const evidenceRisk = (evidenceCounts.expired || 0) + (evidenceCounts.missing || 0);

  const queuedCount = ops?.scan_queue?.queued || 0;
  const runningCount = ops?.scan_queue?.running || 0;
  const failedRecent = ops?.scan_queue?.failed_recent || 0;
  const workersOnline = ops?.workers?.online || 0;
  const p95Overall = ops?.durations?.p95_ms_overall ?? null;

  const opsTone = () => {
    if (!ops) return "border-border bg-background/40";
    if (workersOnline <= 0 || failedRecent > 0) return "border-rose-500/30 bg-rose-500/10";
    if (queuedCount > 5) return "border-amber-500/30 bg-amber-500/10";
    return "border-emerald-500/30 bg-emerald-500/10";
  };

  const budgetTone = (used: number) => {
    if (used <= 10) return "bg-emerald-500";
    if (used <= 25) return "bg-amber-500";
    return "bg-rose-500";
  };

  const evidenceTone = (row: EvidenceRow) => {
    if (!row.appendix_present) return "border-rose-500/30 bg-rose-500/10 text-rose-700";
    if (row.status === "expired") return "border-rose-500/30 bg-rose-500/10 text-rose-700";
    if (row.status === "expiring") return "border-amber-500/30 bg-amber-500/10 text-amber-700";
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-700";
  };

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Operations Overview</h1>
      <p className="text-sm text-muted-foreground mb-8">Internal administration and SOC operations across all tenants.</p>
      {loading ? (
        <p className="text-sm text-muted-foreground">Loading internal metrics...</p>
      ) : error ? (
        <p className="text-sm text-destructive">{error}</p>
      ) : (
        <>
          {failedScans.length > 0 && (
            <Link
              to="/admin/scan-jobs"
              className="mb-6 block rounded-xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive hover:border-destructive/50"
            >
              {failedScans.length} scan job{failedScans.length > 1 ? "s" : ""} failed. Review failures and retry.
            </Link>
          )}
           <div className="mb-6 grid gap-4 lg:grid-cols-3">
             <div className="glass-card rounded-xl p-5">
               <p className="text-xs text-muted-foreground">Service Request Queue</p>
              <div className="mt-3 grid gap-2 text-sm">
                <div className="flex items-center justify-between">
                  <span>Pending</span>
                  <span className="font-semibold">{pendingRequests.length}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Approved</span>
                  <span className="font-semibold">{approvedRequests.length}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Running</span>
                  <span className="font-semibold">{runningRequests.length}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Completed</span>
                  <span className="font-semibold">{completedRequests.length}</span>
                </div>
                <div className="flex items-center justify-between text-destructive">
                  <span>Failed</span>
                  <span className="font-semibold">{failedRequests.length}</span>
                </div>
              </div>
            </div>
            <div className="glass-card rounded-xl p-5">
              <p className="text-xs text-muted-foreground">Scan Job Health</p>
              <div className="mt-3 grid gap-2 text-sm">
                <div className="flex items-center justify-between">
                  <span>Queued</span>
                  <span className="font-semibold">{queuedJobs.length}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Running</span>
                  <span className="font-semibold">{runningJobs.length}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span>Completed</span>
                  <span className="font-semibold">{scanJobs.filter((job) => job.status === "completed").length}</span>
                </div>
                <div className="flex items-center justify-between text-destructive">
                  <span>Failed</span>
                  <span className="font-semibold">{failedScans.length}</span>
                </div>
              </div>
            </div>
             <div className="glass-card rounded-xl p-5">
               <p className="text-xs text-muted-foreground">Operational Notes</p>
               <ul className="mt-3 space-y-2 text-xs text-muted-foreground">
                 <li>Review pending approvals within 24 hours to keep SLAs intact.</li>
                 <li>Escalate failed scans with impact over High severity.</li>
                 <li>Prioritize report delivery for executive stakeholders.</li>
               </ul>
             </div>
            </div>

           <div className="mb-6 grid gap-4 lg:grid-cols-3">
             <button
               type="button"
               onClick={() => setActiveOps("queue")}
               className={`glass-card rounded-xl p-5 text-left transition hover:border-primary/30 hover:bg-primary/5 ${opsTone()}`}
             >
               <div className="flex items-center justify-between mb-2">
                 <span className="text-xs font-medium text-muted-foreground">Scan Queue</span>
                 <ClipboardList className="h-4 w-4 text-primary" />
               </div>
               <div className="grid grid-cols-3 gap-3 text-sm">
                 <div>
                   <div className="text-xs text-muted-foreground">Queued</div>
                   <div className="font-display text-xl font-bold">{queuedCount}</div>
                 </div>
                 <div>
                   <div className="text-xs text-muted-foreground">Running</div>
                   <div className="font-display text-xl font-bold">{runningCount}</div>
                 </div>
                 <div>
                   <div className="text-xs text-muted-foreground">Failed ({ops?.window_hours ?? 24}h)</div>
                   <div className="font-display text-xl font-bold text-rose-700">{failedRecent}</div>
                 </div>
               </div>
               <div className="mt-3 flex items-center justify-between text-xs text-muted-foreground">
                 <span>Workers online: {workersOnline}</span>
                 <span>
                   p95 duration: {typeof p95Overall === "number" ? `${Math.round(p95Overall / 1000)}s` : "—"}
                 </span>
               </div>
             </button>

             <button
               type="button"
               onClick={() => setActiveOps("failures")}
               className="glass-card rounded-xl p-5 text-left transition hover:border-primary/30 hover:bg-primary/5"
             >
               <div className="flex items-center justify-between mb-2">
                 <span className="text-xs font-medium text-muted-foreground">Failure Analytics</span>
                 <AlertTriangle className="h-4 w-4 text-primary" />
               </div>
               <div className="font-display text-2xl font-bold">{ops?.failures?.top_reasons?.reduce((a, b) => a + (b.count || 0), 0) ?? 0}</div>
               <div className="mt-1 text-xs text-muted-foreground">Top buckets: {(ops?.failures?.top_reasons || []).slice(0, 3).map((r) => r.code).join(", ") || "—"}</div>
             </button>

             <button
               type="button"
               onClick={() => setActiveOps("budget")}
               className="glass-card rounded-xl p-5 text-left transition hover:border-primary/30 hover:bg-primary/5"
             >
               <div className="flex items-center justify-between mb-2">
                 <span className="text-xs font-medium text-muted-foreground">Safety Budget Telemetry</span>
                 <SlidersHorizontal className="h-4 w-4 text-primary" />
               </div>
               <div className="text-xs text-muted-foreground">Avg validation requests used (by scan type)</div>
               <div className="mt-3 space-y-2">
                 {(ops?.budget?.by_scan_type || []).slice(0, 3).map((row) => (
                   <div key={row.scan_type} className="flex items-center gap-3">
                     <div className="w-20 text-xs text-muted-foreground">{row.scan_type.toUpperCase()}</div>
                     <div className="h-2 flex-1 rounded-full bg-muted/40 overflow-hidden">
                       <div
                         className={`h-2 ${budgetTone(row.avg_validation_requests_used)}`}
                         style={{ width: `${Math.max(0, Math.min(100, (row.avg_validation_requests_used / 40) * 100))}%` }}
                       />
                     </div>
                     <div className="w-12 text-right text-xs text-muted-foreground">{row.avg_validation_requests_used}</div>
                   </div>
                 ))}
                 {(!ops?.budget?.by_scan_type || ops.budget.by_scan_type.length === 0) && (
                   <div className="text-xs text-muted-foreground">No telemetry recorded yet.</div>
                 )}
               </div>
             </button>
           </div>

           <div className="mb-6 grid gap-4 lg:grid-cols-3">
             <button
               type="button"
               onClick={() => setActiveHygiene("inventory")}
               className="glass-card rounded-xl p-5 text-left transition hover:border-primary/30 hover:bg-primary/5"
             >
               <div className="flex items-center justify-between mb-2">
                 <span className="text-xs font-medium text-muted-foreground">Inventory Completeness</span>
                 <ShieldCheck className="h-4 w-4 text-primary" />
               </div>
               <div className="flex items-end justify-between gap-3">
                 <div>
                   <div className="font-display text-2xl font-bold">{avgCompleteness}%</div>
                   <div className="text-xs text-muted-foreground">
                     {lowCompletenessCount} org{lowCompletenessCount === 1 ? "" : "s"} below 60%
                   </div>
                 </div>
                 <div className={`rounded-full border px-2 py-1 text-xs ${scoreTone(avgCompleteness).chip}`}>
                   {avgCompleteness >= 85 ? "Healthy" : avgCompleteness >= 60 ? "At Risk" : "Critical"}
                 </div>
               </div>
               <div className="mt-3 h-2 w-full rounded-full bg-muted/40 overflow-hidden">
                 <div
                   className={`h-2 ${scoreTone(avgCompleteness).bar}`}
                   style={{ width: `${Math.max(0, Math.min(100, avgCompleteness))}%` }}
                 />
               </div>
             </button>

             <button
               type="button"
               onClick={() => setActiveHygiene("stale")}
               className="glass-card rounded-xl p-5 text-left transition hover:border-primary/30 hover:bg-primary/5"
             >
               <div className="flex items-center justify-between mb-2">
                 <span className="text-xs font-medium text-muted-foreground">Stale Assets</span>
                 <CalendarClock className="h-4 w-4 text-primary" />
               </div>
               <div className="flex items-end justify-between gap-3">
                 <div>
                   <div className="font-display text-2xl font-bold">{staleCount}</div>
                   <div className="text-xs text-muted-foreground">No scans in {hygiene?.stale_assets?.threshold_days ?? 14} days</div>
                 </div>
                 <div
                   className={`rounded-full border px-2 py-1 text-xs ${
                     staleCount === 0 ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700" : "border-amber-500/30 bg-amber-500/10 text-amber-700"
                   }`}
                 >
                   {staleCount === 0 ? "Clear" : "Action Needed"}
                 </div>
               </div>
             </button>

              <button
                type="button"
                onClick={() => setActiveHygiene("policy")}
                className="glass-card rounded-xl p-5 text-left transition hover:border-primary/30 hover:bg-primary/5"
              >
               <div className="flex items-center justify-between mb-2">
                 <span className="text-xs font-medium text-muted-foreground">Scan Policy Issues</span>
                 <SlidersHorizontal className="h-4 w-4 text-primary" />
               </div>
               <div className="flex items-end justify-between gap-3">
                 <div>
                   <div className="font-display text-2xl font-bold">{issuesCount}</div>
                   <div className="text-xs text-muted-foreground">Misconfigurations requiring review</div>
                 </div>
                 <div
                   className={`rounded-full border px-2 py-1 text-xs ${
                     issuesCount === 0 ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700" : "border-rose-500/30 bg-rose-500/10 text-rose-700"
                   }`}
                 >
                   {issuesCount === 0 ? "Compliant" : "Misconfigured"}
                 </div>
                </div>
              </button>
            </div>

            <div className="mb-6 grid gap-4 lg:grid-cols-3">
              <button
                type="button"
                onClick={() => setActiveGov("ssrf")}
                className={`glass-card rounded-xl p-5 text-left transition hover:border-primary/30 hover:bg-primary/5 ${
                  ssrfAuditCount > 0 ? "border-amber-500/30 bg-amber-500/10" : "border-emerald-500/30 bg-emerald-500/10"
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-medium text-muted-foreground">High-Risk SSRF Audit</span>
                  <ScrollText className="h-4 w-4 text-primary" />
                </div>
                <div className="font-display text-2xl font-bold">{ssrfAuditCount}</div>
                <div className="mt-1 text-xs text-muted-foreground">Recorded allowlisted internal URL probe attempts</div>
              </button>

              <button
                type="button"
                onClick={() => setActiveGov("policy")}
                className="glass-card rounded-xl p-5 text-left transition hover:border-primary/30 hover:bg-primary/5"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-medium text-muted-foreground">Policy Change Log</span>
                  <History className="h-4 w-4 text-primary" />
                </div>
                <div className="font-display text-2xl font-bold">{policyChangeCount}</div>
                <div className="mt-1 text-xs text-muted-foreground">Organization scan-policy changes (diff-backed)</div>
              </button>

              <button
                type="button"
                onClick={() => setActiveGov("evidence")}
                className={`glass-card rounded-xl p-5 text-left transition hover:border-primary/30 hover:bg-primary/5 ${
                  evidenceRisk > 0 ? "border-rose-500/30 bg-rose-500/10" : evidenceCounts.expiring > 0 ? "border-amber-500/30 bg-amber-500/10" : "border-emerald-500/30 bg-emerald-500/10"
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-medium text-muted-foreground">Evidence Retention</span>
                  <Archive className="h-4 w-4 text-primary" />
                </div>
                <div className="grid grid-cols-4 gap-2 text-sm">
                  <div>
                    <div className="text-xs text-muted-foreground">OK</div>
                    <div className="font-display text-xl font-bold">{evidenceCounts.ok}</div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Expiring</div>
                    <div className="font-display text-xl font-bold text-amber-700">{evidenceCounts.expiring}</div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Expired</div>
                    <div className="font-display text-xl font-bold text-rose-700">{evidenceCounts.expired}</div>
                  </div>
                  <div>
                    <div className="text-xs text-muted-foreground">Missing</div>
                    <div className="font-display text-xl font-bold text-rose-700">{evidenceCounts.missing}</div>
                  </div>
                </div>
              </button>
            </div>

             <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
               {cards.map((card) => {
                 const content = (
                  <>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xs font-medium text-muted-foreground">{card.label}</span>
                    <card.icon className="h-4 w-4 text-primary" />
                  </div>
                  <p className="font-display text-2xl font-bold">{card.value}</p>
                </>
              );

              return (
                <Link
                  key={card.label}
                  to={card.href}
                  className="glass-card rounded-xl p-5 transition hover:border-primary/30 hover:bg-primary/5"
                >
                  {content}
                </Link>
              );
             })}
           </div>

           <Dialog open={activeOps !== null} onOpenChange={(open) => (!open ? setActiveOps(null) : null)}>
            <DialogContent className="max-h-[85vh] max-w-5xl overflow-y-auto">
               <DialogHeader>
                 <DialogTitle>
                   {activeOps === "queue" ? "Scan Queue" : activeOps === "failures" ? "Failure Analytics" : "Safety Budget Telemetry"}
                 </DialogTitle>
                 <DialogDescription>
                   Internal operations signals for the last {ops?.window_hours ?? 24} hours (best-effort worker ping; scanner telemetry depends on executed scans).
                 </DialogDescription>
               </DialogHeader>

               {activeOps === "queue" && (
                 <div className="space-y-4">
                   <div className="grid gap-3 sm:grid-cols-3">
                     <div className="rounded-xl border border-border bg-background/40 p-4">
                       <div className="text-xs text-muted-foreground">Workers Online</div>
                       <div className={`mt-1 font-display text-2xl font-bold ${workersOnline > 0 ? "" : "text-rose-700"}`}>{workersOnline}</div>
                       <div className="mt-2 text-xs text-muted-foreground">{ops?.workers?.ok ? "Celery ping OK" : ops?.workers?.error || "Ping failed"}</div>
                     </div>
                     <div className="rounded-xl border border-border bg-background/40 p-4">
                       <div className="text-xs text-muted-foreground">Oldest Queued</div>
                       <div className="mt-1 font-display text-2xl font-bold">{ops?.scan_queue?.oldest_queued_minutes ?? "—"}</div>
                       <div className="mt-2 text-xs text-muted-foreground">minutes since creation</div>
                     </div>
                     <div className="rounded-xl border border-border bg-background/40 p-4">
                       <div className="text-xs text-muted-foreground">p95 Duration</div>
                       <div className="mt-1 font-display text-2xl font-bold">
                         {typeof ops?.durations?.p95_ms_overall === "number" ? `${Math.round((ops.durations.p95_ms_overall || 0) / 1000)}s` : "—"}
                       </div>
                       <div className="mt-2 text-xs text-muted-foreground">sample size: {ops?.durations?.sample_size ?? 0}</div>
                     </div>
                   </div>

                   <Table>
                     <TableHeader>
                       <TableRow>
                         <TableHead>Status</TableHead>
                         <TableHead>Type</TableHead>
                         <TableHead>Retries</TableHead>
                         <TableHead>Created</TableHead>
                         <TableHead>Failure Reason</TableHead>
                       </TableRow>
                     </TableHeader>
                     <TableBody>
                       {(ops?.scan_queue?.jobs || []).map((j) => (
                         <TableRow key={j.scan_job_id}>
                           <TableCell>
                             <Badge
                               variant="outline"
                               className={`text-xs ${
                                 j.status === "failed"
                                   ? "border-rose-500/30 bg-rose-500/10 text-rose-700"
                                   : j.status === "running"
                                   ? "border-sky-500/30 bg-sky-500/10 text-sky-700"
                                   : "border-amber-500/30 bg-amber-500/10 text-amber-700"
                               }`}
                             >
                               {j.status.toUpperCase()}
                             </Badge>
                           </TableCell>
                           <TableCell className="text-sm">{j.scan_type.toUpperCase()}</TableCell>
                           <TableCell className="text-sm">{j.retries}</TableCell>
                           <TableCell className="text-xs text-muted-foreground">{j.created_at?.slice(0, 19).replace("T", " ")}</TableCell>
                           <TableCell className="text-xs text-muted-foreground">{j.failure_reason || "—"}</TableCell>
                         </TableRow>
                       ))}
                     </TableBody>
                   </Table>
                 </div>
               )}

               {activeOps === "failures" && (
                 <div className="space-y-4">
                   <Table>
                     <TableHeader>
                       <TableRow>
                         <TableHead>Bucket</TableHead>
                         <TableHead>Count</TableHead>
                         <TableHead>Examples</TableHead>
                       </TableRow>
                     </TableHeader>
                     <TableBody>
                       {(ops?.failures?.top_reasons || []).map((r) => (
                         <TableRow key={r.code}>
                           <TableCell className="font-medium">{r.code}</TableCell>
                           <TableCell className="text-sm">{r.count}</TableCell>
                           <TableCell className="text-xs text-muted-foreground">{(r.examples || []).join(" • ") || "—"}</TableCell>
                         </TableRow>
                       ))}
                     </TableBody>
                   </Table>
                 </div>
               )}

               {activeOps === "budget" && (
                 <div className="space-y-4">
                   <p className="text-sm text-muted-foreground">
                     Validation-request usage is derived from the safe active-validation layer (max budget 40 per scan). Port scans are tracked via ports_checked.
                   </p>
                   <Table>
                     <TableHeader>
                       <TableRow>
                         <TableHead>Scan Type</TableHead>
                         <TableHead>Sample</TableHead>
                         <TableHead>Avg Ports Checked</TableHead>
                         <TableHead>Avg Validation Requests Used</TableHead>
                         <TableHead>p95 Validation Requests Used</TableHead>
                       </TableRow>
                     </TableHeader>
                     <TableBody>
                       {(ops?.budget?.by_scan_type || []).map((row) => (
                         <TableRow key={row.scan_type}>
                           <TableCell className="font-medium">{row.scan_type.toUpperCase()}</TableCell>
                           <TableCell className="text-sm">{row.sample_size}</TableCell>
                           <TableCell className="text-sm">{row.avg_ports_checked}</TableCell>
                           <TableCell className="text-sm">{row.avg_validation_requests_used}</TableCell>
                           <TableCell className="text-sm">{row.p95_validation_requests_used}</TableCell>
                         </TableRow>
                       ))}
                     </TableBody>
                   </Table>
                 </div>
               )}
             </DialogContent>
           </Dialog>

           <Dialog open={activeHygiene !== null} onOpenChange={(open) => (!open ? setActiveHygiene(null) : null)}>
             <DialogContent className="max-h-[85vh] max-w-4xl overflow-y-auto">
               <DialogHeader>
                 <DialogTitle>
                   {activeHygiene === "inventory"
                     ? "Inventory Completeness"
                     : activeHygiene === "stale"
                     ? "Stale Assets"
                     : "Scan Policy Issues"}
                 </DialogTitle>
                 <DialogDescription>
                   Coverage and hygiene signals derived from inventory, scan schedules, and organization scan policies.
                 </DialogDescription>
               </DialogHeader>

               {activeHygiene === "inventory" && (
                 <div className="space-y-3">
                   <p className="text-sm text-muted-foreground">
                     Scores are computed per tenant using expected inventory counts (configured in each organization’s Scan Policy). Unconfigured tenants use safe defaults.
                   </p>
                   <Table>
                     <TableHeader>
                       <TableRow>
                         <TableHead>Organization</TableHead>
                         <TableHead>Score</TableHead>
                         <TableHead>Configured</TableHead>
                         <TableHead>Details</TableHead>
                       </TableRow>
                     </TableHeader>
                     <TableBody>
                       {(hygiene?.inventory?.organizations || []).map((row) => {
                         const tone = scoreTone(row.score || 0);
                         return (
                           <TableRow key={row.organization_id}>
                             <TableCell className="font-medium">{row.organization_name}</TableCell>
                             <TableCell>
                               <span className={`inline-flex items-center gap-2 rounded-full border px-2 py-1 text-xs ${tone.chip}`}>
                                 <span className={`h-2 w-2 rounded-full ${tone.bar}`} />
                                 {row.score}%
                               </span>
                             </TableCell>
                             <TableCell>
                               <Badge variant="outline" className="text-xs">
                                 {row.configured ? "Configured" : "Default"}
                               </Badge>
                             </TableCell>
                             <TableCell className="text-xs text-muted-foreground">
                               {row.categories
                                 .filter((c) => c.status !== "ignored")
                                 .map((c) => `${c.key}: ${c.present}/${c.expected}`)
                                 .slice(0, 3)
                                 .join(" • ")}
                               {row.categories.filter((c) => c.status !== "ignored").length > 3 ? " …" : ""}
                             </TableCell>
                           </TableRow>
                         );
                       })}
                     </TableBody>
                   </Table>
                 </div>
               )}

               {activeHygiene === "stale" && (
                 <div className="space-y-3">
                   <div className="flex items-center justify-between gap-3">
                     <p className="text-sm text-muted-foreground">
                       Assets with no completed scan in the last {hygiene?.stale_assets?.threshold_days ?? 14} days.
                     </p>
                     <Badge variant="outline" className="text-xs">
                       Showing top {hygiene?.stale_assets?.results?.length ?? 0}
                     </Badge>
                   </div>
                   <Table>
                     <TableHeader>
                       <TableRow>
                         <TableHead>Organization</TableHead>
                         <TableHead>Asset</TableHead>
                         <TableHead>Last Scan</TableHead>
                         <TableHead>Schedule</TableHead>
                         <TableHead />
                       </TableRow>
                     </TableHeader>
                     <TableBody>
                       {(hygiene?.stale_assets?.results || []).map((row) => (
                         <TableRow key={row.asset_id}>
                           <TableCell className="text-sm">{row.organization_name}</TableCell>
                           <TableCell>
                             <div className="font-medium">{row.name}</div>
                             <div className="text-xs text-muted-foreground">{row.identifier}</div>
                           </TableCell>
                           <TableCell className="text-sm text-muted-foreground">
                             {row.last_scanned_at ? row.last_scanned_at.slice(0, 10) : "Never"}
                             {typeof row.age_days === "number" ? ` (${row.age_days}d)` : ""}
                           </TableCell>
                           <TableCell>
                             <Badge
                               variant="outline"
                               className={`text-xs ${
                                 row.has_active_schedule
                                   ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700"
                                   : "border-amber-500/30 bg-amber-500/10 text-amber-700"
                               }`}
                             >
                               {row.has_active_schedule ? "Scheduled" : "Not Scheduled"}
                             </Badge>
                           </TableCell>
                           <TableCell className="text-right">
                             {row.has_active_schedule ? (
                               <Button variant="outline" size="sm" asChild>
                                 <Link to={`/admin/organizations/${row.organization_id}`}>Open Org</Link>
                               </Button>
                             ) : (
                               <Button size="sm" onClick={() => scheduleAsset(row.asset_id)} disabled={schedulingAssetId === row.asset_id}>
                                 {schedulingAssetId === row.asset_id ? "Scheduling..." : "Schedule"}
                               </Button>
                             )}
                           </TableCell>
                         </TableRow>
                       ))}
                     </TableBody>
                   </Table>
                 </div>
               )}

                {activeHygiene === "policy" && (
                  <div className="space-y-3">
                    <p className="text-sm text-muted-foreground">
                      Guardrail misconfigurations that can block scans (e.g., wide CIDR), or allow risky modes without proper controls.
                    </p>
                   <Table>
                     <TableHeader>
                       <TableRow>
                         <TableHead>Severity</TableHead>
                         <TableHead>Organization</TableHead>
                         <TableHead>Issue</TableHead>
                         <TableHead>Detail</TableHead>
                       </TableRow>
                     </TableHeader>
                     <TableBody>
                       {(hygiene?.policy_issues?.results || []).map((it, idx) => (
                         <TableRow key={`${it.organization_id}-${it.code}-${idx}`}>
                           <TableCell>
                             <span className={`inline-flex items-center rounded-full border px-2 py-1 text-xs ${issueTone(it.severity)}`}>
                               {it.severity.toUpperCase()}
                             </span>
                           </TableCell>
                           <TableCell className="text-sm">{it.organization_name}</TableCell>
                           <TableCell className="font-medium">{it.title}</TableCell>
                           <TableCell className="text-xs text-muted-foreground">{it.detail}</TableCell>
                         </TableRow>
                       ))}
                     </TableBody>
                   </Table>
                  </div>
                )}
              </DialogContent>
            </Dialog>

            <Dialog open={activeGov !== null} onOpenChange={(open) => (!open ? setActiveGov(null) : null)}>
              <DialogContent className="max-h-[85vh] max-w-5xl overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>
                    {activeGov === "ssrf" ? "High-Risk SSRF Audit Feed" : activeGov === "policy" ? "Policy Change Log" : "Evidence Retention Status"}
                  </DialogTitle>
                  <DialogDescription>
                    Governance telemetry is derived from ActivityLog and report appendix generation. High-risk SSRF attempts are allowlisted and auditable.
                  </DialogDescription>
                </DialogHeader>

                {activeGov === "ssrf" && (
                  <div className="space-y-3">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Time</TableHead>
                          <TableHead>Organization</TableHead>
                          <TableHead>Authorization Ref</TableHead>
                          <TableHead>Requester</TableHead>
                          <TableHead>Attempts</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {(ssrfAudit?.results || []).map((row) => (
                          <TableRow key={row.id}>
                            <TableCell className="text-xs text-muted-foreground">{row.timestamp?.slice(0, 19).replace("T", " ")}</TableCell>
                            <TableCell className="text-sm">{row.organization_name}</TableCell>
                            <TableCell className="text-xs font-mono">{row.authorization_reference || "—"}</TableCell>
                            <TableCell className="text-xs text-muted-foreground">{row.requester_email || "—"}</TableCell>
                            <TableCell className="text-xs">
                              <details className="rounded-lg border border-border bg-background/40 px-3 py-2">
                                <summary className="cursor-pointer select-none text-xs">
                                  {row.attempts_count} attempt{row.attempts_count === 1 ? "" : "s"}
                                  {row.truncated ? " (truncated)" : ""}
                                </summary>
                                <div className="mt-2 space-y-2">
                                  {(row.attempts || []).slice(0, 20).map((a, idx) => (
                                    <div key={`${row.id}-${idx}`} className="rounded-md border border-border bg-background/60 p-2">
                                      <div className="text-[11px] text-muted-foreground">parameter: <span className="font-mono">{a.parameter || "—"}</span></div>
                                      <div className="mt-1 text-[11px] text-muted-foreground">ssrf_target: <span className="font-mono break-all">{a.ssrf_target || "—"}</span></div>
                                      <div className="mt-1 text-[11px] text-muted-foreground">probe_url: <span className="font-mono break-all">{a.probe_url || "—"}</span></div>
                                    </div>
                                  ))}
                                </div>
                              </details>
                            </TableCell>
                          </TableRow>
                        ))}
                        {(!ssrfAudit?.results || ssrfAudit.results.length === 0) && (
                          <TableRow>
                            <TableCell colSpan={5} className="text-sm text-muted-foreground">
                              No high-risk SSRF audit entries recorded.
                            </TableCell>
                          </TableRow>
                        )}
                      </TableBody>
                    </Table>
                  </div>
                )}

                {activeGov === "policy" && (
                  <div className="space-y-3">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Time</TableHead>
                          <TableHead>Organization</TableHead>
                          <TableHead>Changed By</TableHead>
                          <TableHead>Changes</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {(policyChanges?.results || []).map((row) => (
                          <TableRow key={row.id}>
                            <TableCell className="text-xs text-muted-foreground">{row.timestamp?.slice(0, 19).replace("T", " ")}</TableCell>
                            <TableCell className="text-sm">{row.organization_name}</TableCell>
                            <TableCell className="text-xs text-muted-foreground">{row.changed_by_email || "—"}</TableCell>
                            <TableCell className="text-xs">
                              <details className="rounded-lg border border-border bg-background/40 px-3 py-2">
                                <summary className="cursor-pointer select-none text-xs">
                                  {(row.diff?.changed_fields || []).length} field{(row.diff?.changed_fields || []).length === 1 ? "" : "s"} changed
                                </summary>
                                <div className="mt-2 space-y-3">
                                  <div className="text-xs text-muted-foreground">
                                    changed_fields: <span className="font-mono">{(row.diff?.changed_fields || []).join(", ") || "—"}</span>
                                  </div>
                                  {row.diff?.allowlist_changes && (
                                    <div className="space-y-2">
                                      <div className="text-xs font-medium">Allowlist</div>
                                      {Object.entries(row.diff.allowlist_changes).map(([bucket, change]) => (
                                        <div key={`${row.id}-${bucket}`} className="rounded-md border border-border bg-background/60 p-2">
                                          <div className="text-xs text-muted-foreground">{bucket.toUpperCase()}</div>
                                          <div className="mt-1 text-[11px] text-muted-foreground">
                                            added: <span className="font-mono">{(change.added || []).slice(0, 8).join(", ") || "—"}</span>
                                          </div>
                                          <div className="mt-1 text-[11px] text-muted-foreground">
                                            removed: <span className="font-mono">{(change.removed || []).slice(0, 8).join(", ") || "—"}</span>
                                          </div>
                                        </div>
                                      ))}
                                    </div>
                                  )}
                                  {row.diff?.inventory_changes && row.diff.inventory_changes.length > 0 && (
                                    <div className="space-y-2">
                                      <div className="text-xs font-medium">Inventory Expectations</div>
                                      <div className="grid gap-2 sm:grid-cols-2">
                                        {row.diff.inventory_changes.slice(0, 8).map((c) => (
                                          <div key={`${row.id}-${c.key}`} className="rounded-md border border-border bg-background/60 p-2">
                                            <div className="text-xs text-muted-foreground">{c.key}</div>
                                            <div className="mt-1 text-xs font-mono">
                                              {c.before} → {c.after}
                                            </div>
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </details>
                            </TableCell>
                          </TableRow>
                        ))}
                        {(!policyChanges?.results || policyChanges.results.length === 0) && (
                          <TableRow>
                            <TableCell colSpan={4} className="text-sm text-muted-foreground">
                              No scan-policy changes recorded.
                            </TableCell>
                          </TableRow>
                        )}
                      </TableBody>
                    </Table>
                  </div>
                )}

                {activeGov === "evidence" && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-sm text-muted-foreground">
                        Retention window: {evidence?.retention_days ?? 90}d · Expiring soon: {evidence?.expiring_soon_days ?? 7}d
                      </div>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={async () => {
                            try {
                              const refreshed = await apiRequest<EvidenceRetention>("/internal/governance/evidence-retention/?limit=20&refresh=1&cache=1");
                              setEvidence(refreshed);
                            } catch (e) {
                              setError(e instanceof Error ? e.message : "Failed to refresh evidence status.");
                            }
                          }}
                        >
                          Refresh
                        </Button>
                      </div>
                    </div>

                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Status</TableHead>
                          <TableHead>Organization</TableHead>
                          <TableHead>Report</TableHead>
                          <TableHead>Appendix</TableHead>
                          <TableHead>Expires</TableHead>
                          <TableHead />
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {(evidence?.results || []).map((row) => (
                          <TableRow key={row.report_id}>
                            <TableCell>
                              <span className={`inline-flex items-center rounded-full border px-2 py-1 text-xs ${evidenceTone(row)}`}>
                                {!row.appendix_present ? "MISSING" : row.status.toUpperCase()}
                              </span>
                            </TableCell>
                            <TableCell className="text-sm">{row.organization_name}</TableCell>
                            <TableCell className="text-xs font-mono">{row.report_id.slice(0, 8)}…</TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {row.appendix_present ? row.appendix_size_human : row.error || "Unavailable"}
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {row.expires_at?.slice(0, 10)} ({row.days_left}d)
                            </TableCell>
                            <TableCell className="text-right">
                              <div className="flex justify-end gap-2">
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => downloadFile(`/internal/reports/${row.report_id}/download/`, `aegis-report-${row.report_id}.pdf`)}
                                >
                                  PDF
                                </Button>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => downloadFile(`/internal/reports/${row.report_id}/appendix/`, `aegis-report-${row.report_id}-appendix.zip`)}
                                  disabled={!row.appendix_present}
                                >
                                  Appendix
                                </Button>
                              </div>
                            </TableCell>
                          </TableRow>
                        ))}
                        {(!evidence?.results || evidence.results.length === 0) && (
                          <TableRow>
                            <TableCell colSpan={6} className="text-sm text-muted-foreground">
                              No reports found for evidence telemetry.
                            </TableCell>
                          </TableRow>
                        )}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </DialogContent>
            </Dialog>
          </>
        )}
      </div>
    );
}
