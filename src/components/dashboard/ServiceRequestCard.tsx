import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { apiRequest } from "@/lib/api";
import { CloudAccount, ServiceRequest } from "@/lib/types";
import { toast } from "@/components/ui/use-toast";

type ServiceType = ServiceRequest["service_type"];
type TargetField = "repository_url" | "domain_url" | "ip_cidr" | "asset" | "cloud_account";

const serviceTypeLabels: Record<ServiceType, string> = {
  CODE_SECRETS_SCAN: "Code Secrets Scan",
  DEPENDENCY_VULN_SCAN: "Dependency Vulnerability Scan",
  CODE_COMPLIANCE_SCAN: "Code Standards Compliance (Full)",
  CODE_COMPLIANCE_PYTHON: "Python PEP8 Compliance",
  CODE_COMPLIANCE_HTML: "HTML Standards Compliance",
  CODE_COMPLIANCE_CSS: "CSS Standards Compliance",
  CODE_COMPLIANCE_JAVASCRIPT: "JavaScript Standards Compliance",
  CODE_COMPLIANCE_REACT: "React Standards Compliance",
  NETWORK_CONFIGURATION_SCAN: "Network Configuration Scan",
  WEB_EXPOSURE_SCAN: "Web Exposure Scan",
  API_SECURITY_SCAN: "API Security Scan",
  INFRASTRUCTURE_HARDENING_SCAN: "Infrastructure Hardening Scan",
  CLOUD_POSTURE_SCAN: "Cloud Posture Scan",
};

interface ServiceRequestCardProps {
  title: string;
  description: string;
  serviceType?: ServiceType;
  serviceOptions?: Array<{ value: ServiceType; label: string; targetField?: TargetField; targetPlaceholder?: string }>;
  targetField?: TargetField;
  allowedRoles?: Array<"Security Lead" | "Developer" | "Executive">;
  accessRole?: string | null;
  helperText?: string;
  targetPlaceholder?: string;
  justificationPlaceholder?: string;
  cloudAccounts?: CloudAccount[];
}

export function ServiceRequestCard({
  title,
  description,
  serviceType,
  serviceOptions,
  targetField = "domain_url",
  allowedRoles,
  accessRole,
  helperText,
  targetPlaceholder = "Target (repo URL, domain, IP range, service)",
  justificationPlaceholder = "Describe scope, business impact, and any relevant context.",
  cloudAccounts = [],
}: ServiceRequestCardProps) {
  const [target, setTarget] = useState("");
  const [justification, setJustification] = useState("");
  const [selectedServiceType, setSelectedServiceType] = useState<ServiceType>(
    serviceType || serviceOptions?.[0]?.value || "CODE_SECRETS_SCAN"
  );
  const [highRiskSsrf, setHighRiskSsrf] = useState(false);
  const [ownershipConfirmed, setOwnershipConfirmed] = useState(false);
  const [authorizationReference, setAuthorizationReference] = useState("");
  const [authorizationNotes, setAuthorizationNotes] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const canRequest = !allowedRoles || (accessRole ? allowedRoles.includes(accessRole as "Security Lead" | "Developer" | "Executive") : false);

  const activeOption = serviceOptions?.find((option) => option.value === selectedServiceType);
  const effectiveTargetField = activeOption?.targetField || targetField;
  const effectiveTargetPlaceholder = activeOption?.targetPlaceholder || targetPlaceholder;
  const noCloudAccounts = effectiveTargetField === "cloud_account" && cloudAccounts.length === 0;
  const supportsHighRiskSsrf = selectedServiceType === "WEB_EXPOSURE_SCAN" || selectedServiceType === "API_SECURITY_SCAN";

  const handleSubmit = async () => {
    setError(null);
    setSuccess(null);
    if (!canRequest) {
      setError("Your role does not allow this request type.");
      return;
    }
    if (noCloudAccounts) {
      setError("No cloud accounts are configured yet. Ask a platform admin to add one.");
      return;
    }
    const trimmedTarget = target.trim();
    if (!trimmedTarget) {
      setError("Please provide a target to scope the request.");
      return;
    }
    const trimmedJustification = justification.trim();
    if (!trimmedJustification) {
      setError("Please provide a justification for this request.");
      return;
    }
    if (supportsHighRiskSsrf && highRiskSsrf && !ownershipConfirmed) {
      setError("To enable high-risk SSRF validation, you must confirm you own/are authorized to test this target.");
      return;
    }
    if (supportsHighRiskSsrf && highRiskSsrf && !authorizationReference.trim()) {
      setError("To enable high-risk SSRF validation, provide an authorization reference (ticket/change request ID).");
      return;
    }
    setSubmitting(true);
    try {
      const payload: Record<string, unknown> = {
        service_type: selectedServiceType,
        justification: trimmedJustification,
      };
      if (effectiveTargetField === "repository_url") {
        payload.repository_url = trimmedTarget;
        payload.scope = "repository";
      } else if (effectiveTargetField === "ip_cidr") {
        payload.ip_cidr = trimmedTarget;
        payload.scope = "ip_cidr";
      } else if (effectiveTargetField === "asset") {
        payload.asset = trimmedTarget;
        payload.scope = "asset";
      } else if (effectiveTargetField === "cloud_account") {
        payload.cloud_account = trimmedTarget;
        payload.scope = "cloud";
      } else {
        payload.domain_url = trimmedTarget;
        payload.scope = "domain";
      }

      if (supportsHighRiskSsrf) {
        payload.high_risk_ssrf = Boolean(highRiskSsrf);
        payload.ownership_confirmed = Boolean(ownershipConfirmed);
        payload.authorization_reference = authorizationReference.trim();
        payload.authorization_notes = authorizationNotes.trim();
      }

      await apiRequest("/service-requests/", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setTarget("");
      setJustification("");
      setHighRiskSsrf(false);
      setOwnershipConfirmed(false);
      setAuthorizationReference("");
      setAuthorizationNotes("");
      setSuccess("Request submitted. The platform team will review and respond with findings.");
      toast({
        title: "Request submitted",
        description: "Your request has been sent. The platform admin will review it shortly.",
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to submit request.";
      setError(message);
      toast({
        title: "Request failed",
        description: message,
        variant: "destructive",
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="glass-card rounded-xl p-6 mb-8">
      <div className="flex flex-wrap items-start justify-between gap-2 mb-2">
        <div>
          <h2 className="font-display text-lg font-semibold">{title}</h2>
          <p className="text-xs text-muted-foreground mt-1">{serviceTypeLabels[selectedServiceType]}</p>
        </div>
        {helperText && <span className="text-xs text-muted-foreground">{helperText}</span>}
      </div>
      <p className="text-sm text-muted-foreground mb-4">{description}</p>
      {error && <p className="text-sm text-destructive mb-3">{error}</p>}
      {success && <p className="text-sm text-success mb-3">{success}</p>}
      {accessRole && !canRequest && (
        <p className="text-xs text-muted-foreground mb-3">
          Requesting this service is limited to {allowedRoles?.join(", ") || "authorized roles"}.
        </p>
      )}
       {serviceOptions && serviceOptions.length > 1 && (
        <div className="mb-3">
          <label className="text-xs font-medium text-muted-foreground">Service type</label>
          <select
            className="mt-1 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
            value={selectedServiceType}
            onChange={(e) => setSelectedServiceType(e.target.value as ServiceType)}
          >
            {serviceOptions.map((option) => (
              <option key={option.value} value={option.value}>{option.label}</option>
            ))}
          </select>
        </div>
      )}
      <div className="grid gap-3 md:grid-cols-[1fr_auto]">
        {effectiveTargetField === "cloud_account" ? (
          <select
            className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
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
            placeholder={effectiveTargetPlaceholder}
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
        )}
        <Button onClick={handleSubmit} disabled={submitting || !canRequest || noCloudAccounts}>
          {submitting ? "Submitting..." : "Request Service"}
        </Button>
      </div>
      {noCloudAccounts && (
        <p className="mt-2 text-xs text-muted-foreground">
          No cloud accounts are configured yet. Ask the platform admin to add a cloud account before requesting a cloud scan.
        </p>
      )}

      {supportsHighRiskSsrf && (
        <div className="mt-4 rounded-lg border border-border bg-background/40 p-3">
          <p className="text-xs text-muted-foreground mb-2">
            Advanced validation: High-risk SSRF checks are disabled by default and only run for allowlisted, owned targets.
            Enabling this may cause the application to attempt internal URL fetches; all attempts are logged.
          </p>
          <div className="flex items-start gap-3">
            <Checkbox
              id="highRiskSsrf"
              checked={highRiskSsrf}
              onCheckedChange={(checked) => {
                const next = Boolean(checked);
                setHighRiskSsrf(next);
                if (!next) {
                  setOwnershipConfirmed(false);
                  setAuthorizationReference("");
                  setAuthorizationNotes("");
                }
              }}
            />
            <div className="grid gap-2">
              <Label htmlFor="highRiskSsrf" className="text-sm">
                Enable high-risk SSRF validation (authorized targets only)
              </Label>
              {highRiskSsrf && (
                <div className="grid gap-3">
                  <div className="flex items-start gap-3">
                    <Checkbox
                      id="ownershipConfirmed"
                      checked={ownershipConfirmed}
                      onCheckedChange={(checked) => setOwnershipConfirmed(Boolean(checked))}
                    />
                    <Label htmlFor="ownershipConfirmed" className="text-sm">
                      I confirm I own/am authorized to test this target (required)
                    </Label>
                  </div>
                  <div className="grid gap-2 md:grid-cols-2">
                    <div>
                      <Label htmlFor="authorizationReference" className="text-xs text-muted-foreground">
                        Authorization reference (required)
                      </Label>
                      <Input
                        id="authorizationReference"
                        placeholder="e.g., CHG-10492, JIRA-SEC-118, SIGNED-SOW-2026-02"
                        value={authorizationReference}
                        onChange={(e) => setAuthorizationReference(e.target.value)}
                      />
                    </div>
                    <div>
                      <Label htmlFor="authorizationNotes" className="text-xs text-muted-foreground">
                        Authorization notes (optional)
                      </Label>
                      <Input
                        id="authorizationNotes"
                        placeholder="Any constraints / contacts / window"
                        value={authorizationNotes}
                        onChange={(e) => setAuthorizationNotes(e.target.value)}
                      />
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
      <div className="mt-3">
        <Textarea
          placeholder={justificationPlaceholder}
          value={justification}
          onChange={(e) => setJustification(e.target.value)}
        />
      </div>
    </div>
  );
}
