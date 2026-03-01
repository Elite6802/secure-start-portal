import { useEffect, useRef, useState } from "react";
import { PaginatedResponse, apiRequest, unwrapResults } from "@/lib/api";
import { ActivityLogItem, CloudAccount, ScanJob, ServiceRequest } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { toast } from "@/components/ui/use-toast";

const STATUS_LABELS: Record<string, string> = {
  PENDING: "Pending",
  APPROVED: "Approved",
  REJECTED: "Rejected",
  RUNNING: "In Progress",
  COMPLETED: "Completed",
  FAILED: "Failed",
};

const SERVICE_TYPE_LABELS: Record<string, string> = {
  CODE_SECRETS_SCAN: "Code Secrets Scan",
  DEPENDENCY_VULN_SCAN: "Dependency Vulnerability Scan",
  CODE_COMPLIANCE_SCAN: "Code Standards Compliance",
  NETWORK_CONFIGURATION_SCAN: "Network Configuration Scan",
  WEB_EXPOSURE_SCAN: "Web Exposure Scan",
  API_SECURITY_SCAN: "API Security Scan",
  INFRASTRUCTURE_HARDENING_SCAN: "Infrastructure Hardening Scan",
  CLOUD_POSTURE_SCAN: "Cloud Posture Scan",
};

export default function ServiceRequestsAdmin() {
  const [requests, setRequests] = useState<ServiceRequest[]>([]);
  const [cloudAccounts, setCloudAccounts] = useState<CloudAccount[]>([]);
  const [scanJobs, setScanJobs] = useState<ScanJob[]>([]);
  const [activityLogs, setActivityLogs] = useState<ActivityLogItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeStatus, setActiveStatus] = useState<ServiceRequest["status"]>("PENDING");
  const [terminalVisible, setTerminalVisible] = useState<Record<string, boolean>>({});
  const [terminalStreamLines, setTerminalStreamLines] = useState<
    Record<string, Array<{ level: "info" | "ok" | "warn" | "err"; ts: string; text: string }>>
  >({});
  const streamReconnectTimers = useRef<Record<string, number>>({});
  const streamCursors = useRef<Record<string, string>>({});

  const load = async (silent = false) => {
    if (!silent) {
      setLoading(true);
    }
    try {
      const [requestData, cloudData, scanJobData, activityData] = await Promise.all([
        apiRequest<PaginatedResponse<ServiceRequest>>("/internal/service-requests/"),
        apiRequest<PaginatedResponse<CloudAccount>>("/cloud-accounts/"),
        apiRequest<PaginatedResponse<ScanJob>>("/internal/scan-jobs/"),
        apiRequest<PaginatedResponse<ActivityLogItem>>("/internal/activity-log/"),
      ]);
      const results = unwrapResults<ServiceRequest>(requestData).sort((a, b) => {
        const aTime = a.created_at ? new Date(a.created_at).getTime() : 0;
        const bTime = b.created_at ? new Date(b.created_at).getTime() : 0;
        return bTime - aTime;
      });
      setRequests(results);
      setCloudAccounts(unwrapResults<CloudAccount>(cloudData));
      setScanJobs(unwrapResults<ScanJob>(scanJobData));
      setActivityLogs(unwrapResults<ActivityLogItem>(activityData));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load service requests.");
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    load();
    const interval = window.setInterval(() => {
      load(true);
    }, 10000);
    return () => {
      window.clearInterval(interval);
      Object.values(streamReconnectTimers.current).forEach((timer) => window.clearTimeout(timer));
    };
  }, []);

  const handleApprove = async (id: string) => {
    setError(null);
    try {
      await apiRequest(`/internal/service-requests/${id}/approve/`, { method: "POST" });
      await load(true);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to approve service request.");
    }
  };

  const handleStart = async (id: string) => {
    setError(null);
    try {
      await apiRequest(`/internal/service-requests/${id}/start/`, { method: "POST" });
      await load(true);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to start service request.");
    }
  };

  const handleReject = async (id: string) => {
    setError(null);
    try {
      await apiRequest(`/internal/service-requests/${id}/reject/`, { method: "POST" });
      await load(true);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to reject service request.");
    }
  };

  const handlePublish = async (reportId: string) => {
    setError(null);
    try {
      await apiRequest(`/internal/reports/${reportId}/publish/`, { method: "POST" });
      await load(true);
      toast({
        title: "Report delivered",
        description: "The report is now visible to the client.",
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to publish report.";
      setError(message);
      toast({
        title: "Publish failed",
        description: message,
        variant: "destructive",
      });
    }
  };

  const handleSendFeedback = async (request: ServiceRequest) => {
    setError(null);
    const defaultMessage = request.scan_failure_reason
      ? `Your scan failed with: ${request.scan_failure_reason}. Please adjust your target scope and submit a new request.`
      : "Your scan could not complete. Please review the submitted target and submit a revised request.";
    const message = window.prompt("Send feedback message to this user:", defaultMessage);
    if (message === null) {
      return;
    }
    const trimmed = message.trim();
    if (!trimmed) {
      setError("Feedback message cannot be empty.");
      return;
    }
    try {
      await apiRequest(`/internal/service-requests/${request.id}/send-feedback/`, {
        method: "POST",
        body: JSON.stringify({
          title: "Scan failed - action required",
          message: trimmed,
          severity: "warning",
        }),
      });
      toast({
        title: "Feedback sent",
        description: "The user has been notified with your feedback.",
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to send feedback.";
      setError(message);
      toast({
        title: "Feedback failed",
        description: message,
        variant: "destructive",
      });
    }
  };

  const statusCounts = requests.reduce<Record<string, number>>((acc, request) => {
    acc[request.status] = (acc[request.status] || 0) + 1;
    return acc;
  }, {});

  const visibleRequests = requests.filter((request) => request.status === activeStatus);

  const formatTerminalTime = (value: string | null | undefined) => {
    if (!value) return "--:--:--";
    const dt = new Date(value);
    if (Number.isNaN(dt.getTime())) return "--:--:--";
    return dt.toLocaleTimeString([], { hour12: false });
  };

  const stopTerminalStream = (requestId: string) => {
    const timer = streamReconnectTimers.current[requestId];
    if (timer) {
      window.clearTimeout(timer);
      delete streamReconnectTimers.current[requestId];
    }
    delete streamCursors.current[requestId];
  };

  const appendTerminalLine = (
    requestId: string,
    line: { level: "info" | "ok" | "warn" | "err"; ts: string; text: string },
  ) => {
    setTerminalStreamLines((prev) => {
      const current = prev[requestId] || [];
      return {
        ...prev,
        [requestId]: [...current, line].slice(-300),
      };
    });
  };

  const startTerminalStream = (requestId: string) => {
    stopTerminalStream(requestId);
    const poll = async () => {
      try {
        const query = streamCursors.current[requestId]
          ? `?since=${encodeURIComponent(streamCursors.current[requestId])}`
          : "";
        const response = await apiRequest<{
          lines: Array<{ level: "info" | "ok" | "warn" | "err"; ts: string; text: string }>;
          cursor?: string;
        }>(`/internal/service-requests/${requestId}/terminal-stream/${query}`, {
          method: "GET",
        });
        for (const line of response.lines || []) {
          appendTerminalLine(requestId, line);
        }
        if (response.cursor) {
          streamCursors.current[requestId] = response.cursor;
        }
      } catch (err) {
        if (terminalVisible[requestId]) {
          appendTerminalLine(requestId, {
            level: "err",
            ts: new Date().toISOString(),
            text: err instanceof Error ? `STREAM_ERROR  ${err.message}` : "STREAM_ERROR  polling failed",
          });
        }
      }

      if (terminalVisible[requestId]) {
        const timer = window.setTimeout(poll, 2000);
        streamReconnectTimers.current[requestId] = timer;
      }
    };

    void poll();
  };

  const terminalLinesFor = (request: ServiceRequest) => {
    const linkedJob = request.linked_scan_job
      ? scanJobs.find((job) => job.id === request.linked_scan_job)
      : undefined;

    const matchedLogs = activityLogs
      .filter((log) => {
        const metadata = (log.metadata || {}) as Record<string, unknown>;
        const requestRef = String(metadata.service_request ?? metadata.service_request_id ?? "");
        const scanJobRef = String(metadata.scan_job ?? metadata.scan_job_id ?? "");
        return (
          requestRef === request.id ||
          (request.linked_scan_job ? scanJobRef === request.linked_scan_job : false)
        );
      })
      .sort((a, b) => {
        const aTime = a.timestamp ? new Date(a.timestamp).getTime() : 0;
        const bTime = b.timestamp ? new Date(b.timestamp).getTime() : 0;
        return aTime - bTime;
      });

    const lines: Array<{ level: "info" | "ok" | "warn" | "err"; ts: string; text: string }> = [];
    lines.push({
      level: "info",
      ts: formatTerminalTime(request.created_at),
      text: `REQUEST_INIT  service=${request.service_type}  target=${request.domain_url || request.ip_cidr || request.repository_url || request.asset_name || request.asset || "-"}`,
    });
    if (request.high_risk_ssrf) {
      lines.push({
        level: "warn",
        ts: formatTerminalTime(request.created_at),
        text: `HIGH_RISK_SSRF  enabled=true  ownership_confirmed=${Boolean(request.ownership_confirmed)}`,
      });
    }
    lines.push({
      level: request.status === "FAILED" ? "err" : request.status === "COMPLETED" ? "ok" : "info",
      ts: formatTerminalTime(request.updated_at),
      text: `REQUEST_STATUS  ${request.status}`,
    });

    if (linkedJob) {
      lines.push({
        level: linkedJob.status === "failed" ? "err" : linkedJob.status === "completed" ? "ok" : "info",
        ts: formatTerminalTime(linkedJob.created_at),
        text: `JOB_BOUND  id=${linkedJob.id}  type=${linkedJob.scan_type}  state=${linkedJob.status}`,
      });
      if (linkedJob.started_at) {
        lines.push({
          level: "info",
          ts: formatTerminalTime(linkedJob.started_at),
          text: "JOB_START  scanner worker picked up task",
        });
      }
      if (linkedJob.completed_at && linkedJob.status === "completed") {
        lines.push({
          level: "ok",
          ts: formatTerminalTime(linkedJob.completed_at),
          text: `JOB_COMPLETE  findings=${linkedJob.findings_total ?? 0}  duration=${linkedJob.duration_seconds ?? "-"}s`,
        });
      }
      if (linkedJob.status === "failed") {
        lines.push({
          level: "err",
          ts: formatTerminalTime(linkedJob.completed_at || request.updated_at),
          text: `JOB_FAIL  ${linkedJob.failure_reason || "Unknown failure reason"}`,
        });
      }
    } else if (request.status === "RUNNING" || request.status === "APPROVED") {
      lines.push({
        level: "warn",
        ts: formatTerminalTime(request.updated_at),
        text: "JOB_WAIT  waiting for linked scan job assignment",
      });
    }

    for (const log of matchedLogs.slice(-20)) {
      const raw = `${log.action}${log.detail ? ` :: ${log.detail}` : ""}`;
      const lowered = raw.toLowerCase();
      let level: "info" | "ok" | "warn" | "err" = "info";
      if (lowered.includes("failed") || lowered.includes("error")) level = "err";
      else if (lowered.includes("completed") || lowered.includes("approved") || lowered.includes("published")) level = "ok";
      else if (lowered.includes("warning") || lowered.includes("rejected")) level = "warn";
      lines.push({
        level,
        ts: formatTerminalTime(log.timestamp),
        text: raw,
      });
    }

    return lines;
  };

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Service Requests</h1>
      <p className="text-sm text-muted-foreground mb-4">
        Review client service requests, approve execution, and publish findings back to the client dashboard once completed.
      </p>

      <div className="mb-4 flex flex-wrap gap-2">
        {(["PENDING", "APPROVED", "RUNNING", "COMPLETED", "FAILED"] as ServiceRequest["status"][]).map((status) => {
          const active = activeStatus === status;
          return (
            <button
              key={status}
              onClick={() => setActiveStatus(status)}
              className={`rounded-full border px-3 py-1 text-xs font-medium transition ${
                active
                  ? "border-primary/40 bg-primary/10 text-primary"
                  : "border-border text-muted-foreground hover:border-primary/30 hover:text-foreground"
              }`}
            >
              {STATUS_LABELS[status]} <span className="text-[11px]">({statusCounts[status] || 0})</span>
            </button>
          );
        })}
      </div>

      {error && <p className="text-sm text-destructive mb-4">{error}</p>}
      {loading && <p className="text-sm text-muted-foreground mb-6">Loading service requests...</p>}

      {!loading && visibleRequests.length === 0 ? (
        <div className="glass-card rounded-xl p-6 text-sm text-muted-foreground">
          No {STATUS_LABELS[activeStatus].toLowerCase()} service requests.
        </div>
      ) : (
        <div className="space-y-4">
          {visibleRequests.map((request) => {
            const cloudAccount = request.cloud_account
              ? cloudAccounts.find((account) => account.id === request.cloud_account)
              : undefined;
            const cloudName = cloudAccount
              ? `${cloudAccount.name} (${cloudAccount.provider.toUpperCase()})`
              : undefined;
            const targetLabel =
              request.repository_url ||
              request.domain_url ||
              request.ip_cidr ||
              request.asset_name ||
              request.asset ||
              cloudName ||
              request.cloud_account ||
              "-";
            return (
            <div key={request.id} className="glass-card rounded-xl p-6">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <p className="text-xs uppercase tracking-wide text-muted-foreground">{SERVICE_TYPE_LABELS[request.service_type] || request.service_type}</p>
                    <Badge
                      variant="outline"
                      className={
                        request.status === "FAILED"
                          ? "border-destructive/40 text-destructive"
                          : request.status === "REJECTED"
                          ? "border-muted-foreground/40 text-muted-foreground"
                          : request.status === "COMPLETED"
                          ? "border-emerald-400/40 text-emerald-300"
                          : "border-primary/40 text-primary"
                      }
                    >
                      {STATUS_LABELS[request.status] || request.status}
                    </Badge>
                  </div>
                  <h2 className="font-display text-lg font-semibold">{targetLabel}</h2>
                  <p className="text-xs text-muted-foreground">Request ID: {request.id}</p>
                </div>
                <div className="text-xs text-muted-foreground">
                  <div>Organization: {request.organization_name || request.organization}</div>
                  <div>Requested by: {request.requested_by_email || request.requested_by || "Unknown"}</div>
                  <div>Requested role: {request.requested_role}</div>
                  <div>Submitted: {request.created_at?.slice(0, 10)}</div>
                </div>
              </div>

              {request.justification && (
                <div className="mt-4 rounded-lg bg-secondary/40 p-4 text-sm text-muted-foreground">
                  <span className="block text-xs font-semibold text-muted-foreground mb-1">Justification</span>
                  {request.justification}
                </div>
              )}
              {request.status === "FAILED" && request.scan_failure_reason && (
                <div className="mt-4 rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
                  <span className="block text-xs font-semibold mb-1">Failure reason</span>
                  {request.scan_failure_reason}
                </div>
              )}

              <div className="mt-4 flex flex-wrap items-center gap-3">
                <Button size="sm" onClick={() => handleApprove(request.id)} disabled={request.status !== "PENDING"}>
                  Approve
                </Button>
                <Button size="sm" variant="secondary" onClick={() => handleStart(request.id)} disabled={request.status !== "APPROVED"}>
                  Start Scan
                </Button>
                <Button size="sm" variant="outline" onClick={() => handleReject(request.id)} disabled={request.status !== "PENDING"}>
                  Reject
                </Button>
                {request.status === "COMPLETED" && request.report_id && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => handlePublish(request.report_id!)}
                    disabled={request.report_client_visible}
                  >
                    {request.report_client_visible ? "Sent to Client" : "Send Report"}
                  </Button>
                )}
                {request.status === "COMPLETED" && !request.report_id && (
                  <span className="text-xs text-muted-foreground">Report generation pending.</span>
                )}
                {request.status === "FAILED" && (
                  <Button size="sm" variant="outline" onClick={() => handleSendFeedback(request)}>
                    Send Feedback
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    const nextVisible = !terminalVisible[request.id];
                    setTerminalVisible((prev) => ({ ...prev, [request.id]: nextVisible }));
                    if (nextVisible) {
                      setTerminalStreamLines((prev) => ({ ...prev, [request.id]: [] }));
                      startTerminalStream(request.id);
                    } else {
                      stopTerminalStream(request.id);
                    }
                  }}
                >
                  {terminalVisible[request.id] ? "Hide Terminal" : "Show Terminal"}
                </Button>
                <span className="text-xs text-muted-foreground sm:ml-auto">Current status: {STATUS_LABELS[request.status] || request.status}</span>
              </div>

              {terminalVisible[request.id] && (
                <div className="mt-4 rounded-lg border border-emerald-500/30 bg-black/90 shadow-[0_0_24px_rgba(16,185,129,0.15)]">
                  <div className="flex items-center justify-between border-b border-emerald-500/20 px-3 py-2 font-mono text-xs">
                    <span className="text-emerald-300">aegis@ops-terminal:{request.id.slice(0, 8)}$ tail -f scanner.log</span>
                    <span className="animate-pulse text-emerald-400">LIVE</span>
                  </div>
                  <div className="max-h-64 overflow-y-auto px-3 py-3 font-mono text-xs leading-6">
                    {(terminalStreamLines[request.id]?.length ? terminalStreamLines[request.id] : terminalLinesFor(request)).map((line, index) => (
                      <div
                        key={`${request.id}-line-${index}`}
                        className={
                          line.level === "err"
                            ? "text-rose-400"
                            : line.level === "ok"
                            ? "text-emerald-300"
                            : line.level === "warn"
                            ? "text-amber-300"
                            : "text-emerald-200/90"
                        }
                      >
                        <span className="text-emerald-500">[{formatTerminalTime(line.ts)}]</span> {line.text}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )})}
        </div>
      )}
    </div>
  );
}

