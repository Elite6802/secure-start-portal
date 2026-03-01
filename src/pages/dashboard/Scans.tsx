import { useEffect, useState } from "react";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState } from "@/components/dashboard/EmptyState";
import { RoleRestricted } from "@/components/dashboard/RoleRestricted";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Info } from "lucide-react";
import { toast } from "@/components/ui/use-toast";
import { PaginatedResponse, apiRequest, unwrapResults } from "@/lib/api";
import { CloudAccount, ScanJob, ServiceRequest } from "@/lib/types";
import { useNavigate, useOutletContext } from "react-router-dom";

const scanTypeLabels: Record<string, string> = {
  web: "Web Scan",
  api: "API Scan",
  code: "Code Security Scan",
  network: "Network Exposure Scan",
  infrastructure: "Infrastructure Scan",
  cloud: "Cloud Posture Scan",
};

const statusLabels: Record<string, string> = {
  pending: "Scheduled",
  running: "In Progress",
  completed: "Completed",
  failed: "Failed",
};

const statusSteps = ["pending", "running", "completed"];

const renderStatusTimeline = (status: string) => {
  const failed = status === "failed";
  return (
    <div className="mt-2 flex flex-wrap items-center gap-1 text-[10px] text-muted-foreground">
      {statusSteps.map((step, idx) => {
        const isActive = status === step;
        const isComplete = statusSteps.indexOf(status) > idx;
        return (
          <div key={step} className="flex items-center gap-1">
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                failed ? "bg-destructive" : isActive ? "bg-primary" : isComplete ? "bg-success" : "bg-muted-foreground/40"
              }`}
            />
            <span className={isActive ? "text-foreground" : ""}>{step}</span>
            {idx < statusSteps.length - 1 && <span className="mx-1">→</span>}
          </div>
        );
      })}
      {failed && <span className="ml-2 text-destructive">failed</span>}
    </div>
  );
};

const requestStatusLabels: Record<string, string> = {
  PENDING: "Pending",
  APPROVED: "Approved",
  REJECTED: "Rejected",
  RUNNING: "Running",
  COMPLETED: "Completed",
  FAILED: "Failed",
};

const serviceTypeLabels: Record<string, string> = {
  CODE_SECRETS_SCAN: "Code Secrets Scan",
  DEPENDENCY_VULN_SCAN: "Dependency Vulnerability Scan",
  CODE_COMPLIANCE_SCAN: "Code Standards Compliance",
  NETWORK_CONFIGURATION_SCAN: "Network Configuration Scan",
  WEB_EXPOSURE_SCAN: "Web Exposure Scan",
  API_SECURITY_SCAN: "API Security Scan",
  INFRASTRUCTURE_HARDENING_SCAN: "Infrastructure Hardening Scan",
  CLOUD_POSTURE_SCAN: "Cloud Posture Scan",
};

const serviceTypeOptions = [
  { value: "CODE_SECRETS_SCAN", label: "Code Secrets Scan" },
  { value: "DEPENDENCY_VULN_SCAN", label: "Dependency Vulnerability Scan" },
  { value: "CODE_COMPLIANCE_SCAN", label: "Code Standards Compliance" },
  { value: "NETWORK_CONFIGURATION_SCAN", label: "Network Configuration Scan" },
  { value: "WEB_EXPOSURE_SCAN", label: "Web Exposure Scan" },
  { value: "API_SECURITY_SCAN", label: "API Security Scan" },
  { value: "INFRASTRUCTURE_HARDENING_SCAN", label: "Infrastructure Hardening Scan" },
  { value: "CLOUD_POSTURE_SCAN", label: "Cloud Posture Scan" },
];

export default function Scans() {
  const { accessRole } = useOutletContext<{ role: string; accessRole?: string | null }>();
  const restricted = accessRole ? accessRole !== "Security Lead" : true;
  const scanCategories = ["Infrastructure", "Web and API", "Code and Dependencies", "Network", "Cloud"];
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [requests, setRequests] = useState<ServiceRequest[]>([]);
  const [loadingScans, setLoadingScans] = useState(true);
  const [loadingRequests, setLoadingRequests] = useState(true);
  const [scanError, setScanError] = useState<string | null>(null);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [cloudAccounts, setCloudAccounts] = useState<CloudAccount[]>([]);
  const [requestForm, setRequestForm] = useState({
    service_type: "CODE_SECRETS_SCAN",
    target: "",
    justification: "",
  });
  const [submitting, setSubmitting] = useState(false);
  const noCloudAccounts = requestForm.service_type === "CLOUD_POSTURE_SCAN" && cloudAccounts.length === 0;
  const scrollToRequest = () => {
    const target = document.getElementById("scan-request-form");
    if (target) {
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  const loadRequests = async (silent = false) => {
    if (!silent) {
      setLoadingRequests(true);
    }
    try {
      const data = await apiRequest<PaginatedResponse<ServiceRequest>>("/service-requests/");
      const results = unwrapResults<ServiceRequest>(data).sort((a, b) => {
        const aTime = a.created_at ? new Date(a.created_at).getTime() : 0;
        const bTime = b.created_at ? new Date(b.created_at).getTime() : 0;
        return bTime - aTime;
      });
      setRequests(results);
    } catch (err: unknown) {
      setRequestError(err instanceof Error ? err.message : "Failed to load service requests.");
    } finally {
      if (!silent) {
        setLoadingRequests(false);
      }
    }
  };

  const loadScans = async () => {
    setLoadingScans(true);
    try {
      const data = await apiRequest<PaginatedResponse<ScanJob>>("/scan-jobs/");
      setScans(unwrapResults<ScanJob>(data));
    } catch (err: unknown) {
      setScanError(err instanceof Error ? err.message : "Failed to load scans.");
    } finally {
      setLoadingScans(false);
    }
  };

  useEffect(() => {
    loadRequests();
    const interval = window.setInterval(() => {
      loadRequests(true);
    }, 15000);
    return () => window.clearInterval(interval);
  }, []);

  useEffect(() => {
    const loadCloudAccounts = async () => {
      try {
        const data = await apiRequest<PaginatedResponse<CloudAccount>>("/cloud-accounts/");
        setCloudAccounts(unwrapResults<CloudAccount>(data));
      } catch {
        setCloudAccounts([]);
      }
    };
    loadCloudAccounts();
  }, []);

  useEffect(() => {
    if (!accessRole || restricted) {
      setLoadingScans(false);
      setScans([]);
      setScanError(null);
      return;
    }
    loadScans();
  }, [accessRole, restricted]);

  const handleRequestSubmit = async () => {
    setRequestError(null);
    if (!requestForm.target.trim()) {
      setRequestError("Please provide a target (repository URL, domain, or IP range).");
      return;
    }
    if (noCloudAccounts) {
      setRequestError("No cloud accounts are configured yet. Ask a platform admin to add one.");
      return;
    }
    if (!requestForm.justification.trim()) {
      setRequestError("Please provide a justification for this request.");
      return;
    }
    setSubmitting(true);
    try {
      const payload: Record<string, string> = {
        service_type: requestForm.service_type,
        justification: requestForm.justification,
      };
      if (requestForm.service_type === "NETWORK_CONFIGURATION_SCAN" || requestForm.service_type === "INFRASTRUCTURE_HARDENING_SCAN") {
        if (requestForm.target.includes("/")) {
          payload.ip_cidr = requestForm.target.trim();
          payload.scope = "ip_cidr";
        } else {
          payload.domain_url = requestForm.target.trim();
          payload.scope = "domain";
        }
      } else if (requestForm.service_type === "CLOUD_POSTURE_SCAN") {
        payload.cloud_account = requestForm.target.trim();
        payload.scope = "cloud";
      } else if (requestForm.service_type === "WEB_EXPOSURE_SCAN" || requestForm.service_type === "API_SECURITY_SCAN") {
        payload.domain_url = requestForm.target.trim();
        payload.scope = "domain";
      } else {
        payload.repository_url = requestForm.target.trim();
        payload.scope = "repository";
      }

      await apiRequest("/service-requests/", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setRequestForm({ service_type: "CODE_SECRETS_SCAN", target: "", justification: "" });
      toast({
        title: "Request submitted",
        description: "The platform admin will review this request and publish findings when complete.",
      });
      await loadRequests(true);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to submit service request.";
      setRequestError(message);
      toast({
        title: "Request failed",
        description: message,
        variant: "destructive",
      });
    } finally {
      setSubmitting(false);
    }
  };

  const navigate = useNavigate();

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Automated Security Scans</h1>
      <p className="text-sm text-muted-foreground mb-4">Centralized view of scheduled and completed security scans across your environment.</p>

      <div id="scan-request-form" className="glass-card rounded-xl p-6 mb-8">
        <div className="flex items-center justify-between mb-2">
          <h2 className="font-display text-lg font-semibold">Request a Security Scan</h2>
          <span className="text-xs text-muted-foreground">All requests are reviewed by the platform security team.</span>
        </div>
        <p className="text-sm text-muted-foreground mb-4">
          Submit a new scan request. The platform admin will perform validation and return findings to your dashboard once complete.
        </p>
        {requestError && <p className="text-sm text-destructive mb-3">{requestError}</p>}
        <div className="grid gap-3 md:grid-cols-3">
          <Select value={requestForm.service_type} onValueChange={(value) => setRequestForm({ ...requestForm, service_type: value })}>
            <SelectTrigger>
              <SelectValue placeholder="Service type" />
            </SelectTrigger>
            <SelectContent>
              {serviceTypeOptions.map((option) => (
                <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          {requestForm.service_type === "CLOUD_POSTURE_SCAN" ? (
            <select
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
              value={requestForm.target}
              onChange={(e) => setRequestForm({ ...requestForm, target: e.target.value })}
              disabled={noCloudAccounts}
            >
              <option value="">Select cloud account</option>
              {cloudAccounts.map((account) => (
                <option key={account.id} value={account.id}>
                  {account.name} ({account.provider.toUpperCase()})
                </option>
              ))}
            </select>
          ) : (
            <Input
              placeholder={
                requestForm.service_type === "NETWORK_CONFIGURATION_SCAN" || requestForm.service_type === "INFRASTRUCTURE_HARDENING_SCAN"
                  ? "Target (domain or IP/CIDR)"
                  : requestForm.service_type === "WEB_EXPOSURE_SCAN" || requestForm.service_type === "API_SECURITY_SCAN"
                  ? "Target domain or URL"
                  : "Repository URL"
              }
              value={requestForm.target}
              onChange={(e) => setRequestForm({ ...requestForm, target: e.target.value })}
            />
          )}
          <Button onClick={handleRequestSubmit} disabled={submitting || noCloudAccounts}>
            {submitting ? "Submitting..." : "Submit Request"}
          </Button>
        </div>
        {noCloudAccounts && (
          <p className="mt-2 text-xs text-muted-foreground">
            No cloud accounts are configured yet. Ask a platform admin to add one before requesting a cloud scan.
          </p>
        )}
        <div className="mt-3">
          <Textarea
            placeholder="Describe scope, business impact, and context for the security team."
            value={requestForm.justification}
            onChange={(e) => setRequestForm({ ...requestForm, justification: e.target.value })}
          />
        </div>
      </div>

      <div className="glass-card rounded-xl p-6 mb-8">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-display text-lg font-semibold">Service Requests</h2>
          <span className="text-xs text-muted-foreground">{requests.length} active request{requests.length === 1 ? "" : "s"}</span>
        </div>
        {loadingRequests && <p className="text-sm text-muted-foreground">Loading service requests...</p>}
        {!loadingRequests && requests.length === 0 && (
          <p className="text-sm text-muted-foreground">No service requests submitted yet.</p>
        )}
        {!loadingRequests && requests.length > 0 && (
          <div className="space-y-3">
            {requests.map((request) => {
              const cloudAccount =
                request.cloud_account
                  ? cloudAccounts.find((account) => account.id === request.cloud_account)
                  : undefined;
              const cloudName = cloudAccount
                ? `${cloudAccount.name} (${cloudAccount.provider.toUpperCase()})`
                : undefined;
              const target =
                request.repository_url ||
                request.domain_url ||
                request.ip_cidr ||
                request.asset ||
                cloudName ||
                request.cloud_account ||
                "-";
              return (
                <div key={request.id} className="rounded-lg border border-border/60 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <p className="text-xs text-muted-foreground">{serviceTypeLabels[request.service_type] || request.service_type}</p>
                      <p className="text-sm font-medium">{target}</p>
                    </div>
                    <StatusBadge status={requestStatusLabels[request.status] || request.status} />
                  </div>
                  <div className="mt-2 text-xs text-muted-foreground flex flex-wrap gap-4">
                    <span>Submitted: {request.created_at?.slice(0, 10)}</span>
                    {request.linked_scan_job && <span>Scan job: {request.linked_scan_job}</span>}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="mb-6 flex flex-wrap gap-2">
        {scanCategories.map((category) => (
          <span key={category} className="rounded-full bg-secondary px-3 py-1 text-xs text-muted-foreground">
            {category}
          </span>
        ))}
      </div>

      {!accessRole && <p className="text-sm text-muted-foreground mb-6">Loading access profile...</p>}
      {accessRole && restricted ? (
        <RoleRestricted
          title="Scan operations restricted"
          description="Full scan execution detail is available to Security Lead users for operational visibility."
        />
      ) : accessRole ? (
        <>
          {loadingScans && <p className="text-sm text-muted-foreground mb-6">Loading scans...</p>}
          {scanError && <p className="text-sm text-destructive mb-6">{scanError}</p>}

          {scans.length === 0 && !loadingScans ? (
            <EmptyState
              title="No scans have been scheduled"
              description="Once baseline scans are configured, this view will show coverage by scan type, timing, and validated findings. Scan history is critical for proving continuous monitoring and audit readiness."
              ctaLabel="Request a scan"
              onAction={scrollToRequest}
            />
          ) : (
            <div className="glass-card rounded-xl overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Scan ID</TableHead>
                    <TableHead>
                      <div className="flex items-center gap-2">
                        Scan Type
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <button className="text-muted-foreground hover:text-foreground" aria-label="Scan types tooltip">
                              <Info className="h-3.5 w-3.5" />
                            </button>
                          </TooltipTrigger>
                          <TooltipContent className="max-w-xs text-xs">
                            Scan types map to infrastructure, web, code, and network coverage domains.
                          </TooltipContent>
                        </Tooltip>
                      </div>
                    </TableHead>
                    <TableHead>Scope</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Assets</TableHead>
                    <TableHead>
                      <div className="flex items-center gap-2">
                        Findings
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <button className="text-muted-foreground hover:text-foreground" aria-label="Findings tooltip">
                              <Info className="h-3.5 w-3.5" />
                            </button>
                          </TooltipTrigger>
                          <TooltipContent className="max-w-xs text-xs">
                            Findings are validated and categorized by impact after triage.
                          </TooltipContent>
                        </Tooltip>
                      </div>
                    </TableHead>
                    <TableHead>Started</TableHead>
                    <TableHead>Completed</TableHead>
                    <TableHead className="text-right">Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {scans.map((scan) => (
                    <TableRow key={scan.id}>
                      <TableCell className="font-mono text-xs">{scan.id}</TableCell>
                      <TableCell className="font-medium text-sm">{scanTypeLabels[scan.scan_type] || scan.scan_type}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {scan.scope_summary || scan.asset_name || scan.repository_url || "-"}
                      </TableCell>
                      <TableCell>
                        <StatusBadge status={statusLabels[scan.status] || scan.status} />
                        {renderStatusTimeline(scan.status)}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">{scan.assets_scanned ?? "-"}</TableCell>
                      <TableCell>
                        {scan.status === "completed" ? (
                          <div className="space-y-1">
                            <div className="flex gap-1.5">
                              <SeverityBadge level="Critical" count={scan.findings_summary?.critical || 0} />
                              <SeverityBadge level="High" count={scan.findings_summary?.high || 0} />
                              <SeverityBadge level="Medium" count={scan.findings_summary?.moderate || 0} />
                              <SeverityBadge level="Low" count={scan.findings_summary?.low || 0} />
                            </div>
                            <p className="text-[11px] text-muted-foreground">
                              {scan.findings_total ?? 0} findings
                              {scan.files_scanned ? ` · ${scan.files_scanned} files` : ""}
                            </p>
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">Not available</span>
                        )}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">{scan.started_at || "Not started"}</TableCell>
                      <TableCell className="text-sm text-muted-foreground">{scan.completed_at || "Not completed"}</TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => navigate(`/dashboard/scans/${scan.id}`)}
                        >
                          View
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </>
      ) : null}
    </div>
  );
}


