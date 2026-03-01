import { useEffect, useMemo, useState } from "react";
import { Link, useOutletContext } from "react-router-dom";
import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { RoleRestricted } from "@/components/dashboard/RoleRestricted";
import { ServiceRequestCard } from "@/components/dashboard/ServiceRequestCard";
import { Info } from "lucide-react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { PaginatedResponse, apiRequest, unwrapResults } from "@/lib/api";
import { CodeFinding, NetworkFinding, Scan, SecurityStatus } from "@/lib/types";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";

type MappingItem = { name: string; status: string };
type MappingDomain = { domain: string; items: MappingItem[] };

type DetailItem = {
  id: string;
  kind: "Code" | "Network";
  severity: string;
  title: string;
  scanJob?: string | null;
};

function severityLabel(severity: string): "Low" | "Medium" | "High" | "Critical" {
  if (severity === "critical") return "Critical";
  if (severity === "high") return "High";
  if (severity === "moderate") return "Medium";
  return "Low";
}

export default function ComplianceMapping() {
  const { accessRole } = useOutletContext<{ role: string; accessRole?: string | null }>();
  const restricted = accessRole ? !["Security Lead", "Executive"].includes(accessRole) : true;
  const isExecutive = accessRole === "Executive";
  const [scans, setScans] = useState<Scan[]>([]);
  const [codeFindings, setCodeFindings] = useState<CodeFinding[]>([]);
  const [networkFindings, setNetworkFindings] = useState<NetworkFinding[]>([]);
  const [complianceSummary, setComplianceSummary] = useState<SecurityStatus["compliance_summary"] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeItem, setActiveItem] = useState<null | { domain: string; item: MappingItem }>(null);

  useEffect(() => {
    const load = async () => {
      try {
        if (!accessRole || restricted) {
          setLoading(false);
          setError(null);
          return;
        }
        setLoading(true);
        if (isExecutive) {
          const statusData = await apiRequest<SecurityStatus>("/security-status/");
          setComplianceSummary(statusData.compliance_summary ?? null);
          setScans([]);
          setCodeFindings([]);
          setNetworkFindings([]);
          return;
        }
        const [scansData, codeFindingsData, networkFindingsData] = await Promise.all([
          apiRequest<PaginatedResponse<Scan>>("/scans/"),
          apiRequest<PaginatedResponse<CodeFinding>>("/code-findings/"),
          apiRequest<PaginatedResponse<NetworkFinding>>("/network-findings/"),
        ]);
        setScans(unwrapResults<Scan>(scansData));
        setCodeFindings(unwrapResults<CodeFinding>(codeFindingsData));
        setNetworkFindings(unwrapResults<NetworkFinding>(networkFindingsData));
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Failed to load compliance data.");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [accessRole, restricted, isExecutive]);

  const complianceMapping: MappingDomain[] = useMemo(() => {
    if (isExecutive && complianceSummary) {
      const executiveStatus = {
        owasp: complianceSummary.owasp_top_10 ?? "Not Assessed",
        iso: complianceSummary.iso_27001 ?? "Not Assessed",
        nist: complianceSummary.nist_800_53 ?? "Not Assessed",
      };
      return [
        {
          domain: "OWASP Top 10 Coverage",
          items: [
            { name: "OWASP Top 10", status: executiveStatus.owasp },
          ],
        },
        {
          domain: "Secure Coding Standards",
          items: [
            { name: "Secure Coding Controls", status: executiveStatus.iso },
          ],
        },
        {
          domain: "Network Security Best Practices",
          items: [
            { name: "Network Security Controls", status: executiveStatus.nist },
          ],
        },
      ];
    }
    const hasScans = scans.length > 0;
    const hasCode = codeFindings.length > 0;
    const hasNetwork = networkFindings.length > 0;
    const statusFor = (covered: boolean) => (covered ? "Partial" : "Not Assessed");

    return [
      {
        domain: "OWASP Top 10 Coverage",
        items: [
          { name: "A01: Access Control", status: statusFor(hasScans) },
          { name: "A02: Cryptographic Failures", status: statusFor(hasScans) },
          { name: "A03: Injection", status: hasCode ? "Covered" : statusFor(hasScans) },
          { name: "A04: Insecure Design", status: statusFor(hasScans) },
          { name: "A05: Security Misconfiguration", status: hasNetwork ? "Partial" : statusFor(hasScans) },
          { name: "A06: Vulnerable Components", status: hasCode ? "Partial" : statusFor(hasScans) },
          { name: "A07: Auth Failures", status: statusFor(hasScans) },
          { name: "A08: Integrity Failures", status: statusFor(hasScans) },
          { name: "A09: Logging and Monitoring", status: statusFor(hasScans) },
          { name: "A10: SSRF", status: statusFor(hasScans) },
        ],
      },
      {
        domain: "Secure Coding Standards",
        items: [
          { name: "Input Validation", status: hasCode ? "Partial" : "Not Assessed" },
          { name: "Secrets Management", status: hasCode ? "Partial" : "Not Assessed" },
          { name: "Error Handling", status: hasCode ? "Covered" : "Not Assessed" },
          { name: "Dependency Hygiene", status: hasCode ? "Partial" : "Not Assessed" },
          { name: "Secure Authentication", status: hasCode ? "Partial" : "Not Assessed" },
        ],
      },
      {
        domain: "Network Security Best Practices",
        items: [
          { name: "Segmentation and Isolation", status: hasNetwork ? "Partial" : "Not Assessed" },
          { name: "Perimeter Hardening", status: hasNetwork ? "Partial" : "Not Assessed" },
          { name: "Service Inventory", status: hasNetwork ? "Covered" : "Not Assessed" },
          { name: "TLS Baseline", status: hasNetwork ? "Partial" : "Not Assessed" },
          { name: "Remote Access Controls", status: hasNetwork ? "Not Assessed" : "Not Assessed" },
        ],
      },
    ];
  }, [scans, codeFindings, networkFindings, isExecutive, complianceSummary]);

  const evidenceForItem = useMemo(() => {
    const code = codeFindings;
    const net = networkFindings;

    const matchCode = (pred: (f: CodeFinding) => boolean) => code.filter(pred);
    const matchNet = (pred: (f: NetworkFinding) => boolean) => net.filter(pred);
    const keyword = (s: string, terms: string[]) => {
      const v = (s || "").toLowerCase();
      return terms.some((t) => v.includes(t));
    };

    // Best-effort, safe mapping heuristics. This is a governance view, not an exploitation engine.
    const rules: Record<string, { code: (f: CodeFinding) => boolean; net: (f: NetworkFinding) => boolean; notes: string[] }> = {
      "A01: Access Control": {
        code: (f) => keyword(f.title + " " + f.description, ["idor", "access control", "authorization", "authz", "permission", "broken access"]),
        net: (f) => keyword(String(f.evidence?.validation_type ?? "") + " " + f.summary, ["access control"]),
        notes: ["Maps authz/BOLA/IDOR indicators and access-control validation signals."],
      },
      "A02: Cryptographic Failures": {
        code: (f) => keyword(f.title + " " + f.description, ["crypto", "cipher", "tls", "ssl", "weak", "hash", "md5", "sha1", "encryption"]),
        net: (f) => keyword(f.summary, ["tls", "ssl", "cipher", "hsts", "certificate"]),
        notes: ["Maps TLS policy/misconfiguration and weak-crypto indicators where detected."],
      },
      "A03: Injection": {
        code: (f) => keyword(f.title + " " + f.description, ["sql", "sqli", "xss", "injection", "command injection", "template injection"]),
        net: (f) => keyword(String(f.evidence?.validation_type ?? "") + " " + f.summary, ["input validation"]),
        notes: ["Maps injection-style signals (SQLi/XSS/injection) observed in code and safe web probes."],
      },
      "A04: Insecure Design": {
        code: (f) => keyword(f.title + " " + f.description, ["insecure design", "threat model", "abuse case", "business logic"]),
        net: (_f) => false,
        notes: ["Insecure design is primarily assessed via threat modeling and architectural review; scan signals are limited."],
      },
      "A05: Security Misconfiguration": {
        code: (f) => keyword(f.title + " " + f.description, ["debug", "misconfig", "configuration", "exposed", "default", "cors"]),
        net: (f) => f.finding_type === "misconfiguration" || keyword(f.summary, ["misconfiguration", "cors", "header", "directory listing"]),
        notes: ["Maps network/web misconfiguration findings and config-related code issues."],
      },
      "A06: Vulnerable Components": {
        code: (f) => f.category === "dependency" || keyword(f.title + " " + f.description, ["cve-", "vulnerable component", "dependency"]),
        net: (_f) => false,
        notes: ["Maps dependency scanner findings and CVE-style signals."],
      },
      "A07: Auth Failures": {
        code: (f) => keyword(f.title + " " + f.description, ["authentication", "jwt", "token", "session", "password"]),
        net: (f) => keyword(String(f.evidence?.validation_type ?? "") + " " + f.summary, ["auth", "cookie", "session"]),
        notes: ["Maps auth/session handling signals (safe heuristics; no brute force)."],
      },
      "A08: Integrity Failures": {
        code: (f) => keyword(f.title + " " + f.description, ["integrity", "signature", "supply chain", "pipeline", "artifact", "checksum"]),
        net: (_f) => false,
        notes: ["Often requires CI/CD and deployment pipeline review; scan signals may be incomplete."],
      },
      "A09: Logging and Monitoring": {
        code: (f) => keyword(f.title + " " + f.description, ["logging", "audit", "monitoring", "alert", "trace", "telemetry"]),
        net: (_f) => false,
        notes: ["Often requires runtime observability review; scan signals may be incomplete."],
      },
      "A10: SSRF": {
        code: (f) => keyword(f.title + " " + f.description, ["ssrf", "server-side request forgery"]),
        net: (f) => keyword(String(f.evidence?.validation_type ?? "") + " " + f.summary, ["ssrf"]),
        notes: ["Maps SSRF indicators from safe probes and code signals. High-risk SSRF is allowlisted and opt-in only."],
      },

      "Input Validation": {
        code: (f) => f.category === "sast" || keyword(f.title + " " + f.description, ["input", "validation", "xss", "sql"]),
        net: (f) => keyword(String(f.evidence?.validation_type ?? "") + " " + f.summary, ["input"]),
        notes: ["Maps SAST and input-handling indicators; coverage depends on scanned repos and endpoints."],
      },
      "Secrets Management": {
        code: (f) => f.category === "secrets" || keyword(f.title + " " + f.description, ["secret", "api key", "credential", "token"]),
        net: (_f) => false,
        notes: ["Maps secrets scanner findings and credential leakage indicators."],
      },
      "Error Handling": {
        code: (f) => keyword(f.title + " " + f.description, ["error handling", "exception", "stack trace", "debug"]),
        net: (f) => keyword(f.summary, ["error", "stack trace", "exception"]),
        notes: ["Maps error leakage indicators where present."],
      },
      "Dependency Hygiene": {
        code: (f) => f.category === "dependency" || keyword(f.title + " " + f.description, ["dependency", "cve-", "outdated"]),
        net: (_f) => false,
        notes: ["Maps dependency scanner results."],
      },
      "Secure Authentication": {
        code: (f) => keyword(f.title + " " + f.description, ["authentication", "jwt", "session", "cookie", "password"]),
        net: (f) => keyword(String(f.evidence?.validation_type ?? "") + " " + f.summary, ["cookie", "session", "auth"]),
        notes: ["Maps auth/session handling indicators; not a brute-force test."],
      },

      "Segmentation and Isolation": {
        code: (_f) => false,
        net: (f) => f.finding_type === "segmentation_risk" || keyword(f.summary, ["segmentation", "isolation"]),
        notes: ["Maps segmentation risk signals and environment exposure indicators."],
      },
      "Perimeter Hardening": {
        code: (_f) => false,
        net: (f) => f.finding_type === "exposed_service" || keyword(f.summary, ["exposed", "internet-facing", "public"]),
        notes: ["Maps exposed-service inventory and perimeter-exposure signals."],
      },
      "Service Inventory": {
        code: (_f) => false,
        net: (f) => f.finding_type === "exposed_service",
        notes: ["Maps exposed service inventory signals (ports/services)."],
      },
      "TLS Baseline": {
        code: (_f) => false,
        net: (f) => f.finding_type === "misconfiguration" && keyword(f.summary, ["tls", "ssl", "hsts", "cipher"]),
        notes: ["Maps TLS-related findings and baseline policy gaps."],
      },
      "Remote Access Controls": {
        code: (_f) => false,
        net: (f) => keyword(f.summary, ["rdp", "ssh", "vpn", "remote access"]),
        notes: ["Maps remote-access surface signals when detected."],
      },
    };

    return (itemName: string) => {
      const rule = rules[itemName];
      if (!rule) {
        return { notes: ["No mapping rule configured yet for this item."], codeMatches: [], netMatches: [], sample: [] as DetailItem[] };
      }
      const codeMatches = matchCode(rule.code);
      const netMatches = matchNet(rule.net);
      const sample: DetailItem[] = [
        ...codeMatches.slice(0, 6).map((f) => ({ id: f.id, kind: "Code" as const, severity: f.severity, title: f.title, scanJob: f.scan_job })),
        ...netMatches.slice(0, 6).map((f) => ({ id: f.id, kind: "Network" as const, severity: f.severity, title: f.summary, scanJob: f.scan_job })),
      ].slice(0, 10);
      return { notes: rule.notes, codeMatches, netMatches, sample };
    };
  }, [codeFindings, networkFindings]);

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Compliance and Standards Mapping</h1>
      <p className="text-sm text-muted-foreground mb-8">Read-only mapping of coverage against recognized security standards.</p>

      <ServiceRequestCard
        title="Request Compliance Mapping Update"
        description="Request a compliance evidence refresh for the selected scope. The security team will validate inputs and update mappings."
        serviceType="DEPENDENCY_VULN_SCAN"
        targetField="domain_url"
        allowedRoles={["Security Lead"]}
        accessRole={accessRole}
        helperText="Requests are reviewed by the platform security team."
        targetPlaceholder="Scope (environment, business unit, application)"
        justificationPlaceholder="Explain the compliance scope and desired evidence refresh window."
      />

      {!accessRole && <p className="text-sm text-muted-foreground mb-6">Loading access profile...</p>}
      {accessRole && restricted && (
        <RoleRestricted
          title="Compliance mapping restricted"
          description="Compliance summaries are available to Security Lead and Executive roles for governance reporting."
        />
      )}
      {accessRole && !restricted && (
        <>
          {loading && <p className="text-sm text-muted-foreground mb-6">Loading compliance mapping...</p>}
          {error && <p className="text-sm text-destructive mb-6">{error}</p>}

          <div className="space-y-6">
            {complianceMapping.map((domain) => (
              <div key={domain.domain} className="glass-card rounded-xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="font-display text-lg font-semibold">{domain.domain}</h2>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <button className="text-muted-foreground hover:text-foreground" aria-label="Standards mapping tooltip">
                        <Info className="h-4 w-4" />
                      </button>
                    </TooltipTrigger>
                    <TooltipContent className="max-w-xs text-xs">
                      Status reflects current evidence collected from scans and policy reviews.
                    </TooltipContent>
                  </Tooltip>
                </div>
                <div className="space-y-3">
                  {domain.items.map((item) => (
                    <button
                      key={item.name}
                      type="button"
                      onClick={() => setActiveItem({ domain: domain.domain, item })}
                      className="flex w-full items-center justify-between rounded-lg bg-secondary/60 px-4 py-3 text-left transition hover:bg-secondary/80 focus:outline-none focus:ring-2 focus:ring-primary/30"
                    >
                      <span className="text-sm text-foreground">{item.name}</span>
                      <StatusBadge status={item.status} />
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>

          <Dialog open={activeItem !== null} onOpenChange={(open) => (!open ? setActiveItem(null) : null)}>
            <DialogContent className="max-w-3xl">
              <DialogHeader>
                <DialogTitle>{activeItem ? activeItem.item.name : "Detail"}</DialogTitle>
                <DialogDescription>
                  {activeItem ? `${activeItem.domain} · ${activeItem.item.status}` : ""}
                </DialogDescription>
              </DialogHeader>

              <ScrollArea className="max-h-[70vh] pr-4">
                {activeItem && (
                  <div className="space-y-5">
                    <div className="rounded-xl border border-border bg-background/60 p-4">
                      <p className="text-sm font-semibold mb-1">What This Means</p>
                      <p className="text-sm text-muted-foreground">
                        This mapping is a governance view derived from scan evidence. “Covered/Partial/Not Assessed” reflects the current
                        evidence available for this control item.
                      </p>
                    </div>

                    {isExecutive ? (
                      <div className="rounded-xl border border-border bg-background/60 p-4">
                        <p className="text-sm font-semibold mb-1">Executive View</p>
                        <p className="text-sm text-muted-foreground">
                          Executive mode shows summary coverage. Switch to a Security Lead role to view evidence details from scan findings.
                        </p>
                      </div>
                    ) : (
                      (() => {
                        const ev = evidenceForItem(activeItem.item.name);
                        return (
                          <>
                            <div className="grid gap-3 sm:grid-cols-3">
                              <div className="rounded-xl border border-border bg-background/60 p-3">
                                <p className="text-xs text-muted-foreground">Scans Considered</p>
                                <p className="mt-1 text-xl font-semibold">{scans.length}</p>
                              </div>
                              <div className="rounded-xl border border-border bg-background/60 p-3">
                                <p className="text-xs text-muted-foreground">Code Evidence</p>
                                <p className="mt-1 text-xl font-semibold">{ev.codeMatches.length}</p>
                              </div>
                              <div className="rounded-xl border border-border bg-background/60 p-3">
                                <p className="text-xs text-muted-foreground">Network Evidence</p>
                                <p className="mt-1 text-xl font-semibold">{ev.netMatches.length}</p>
                              </div>
                            </div>

                            <div className="rounded-xl border border-border bg-background/60 p-4">
                              <p className="text-sm font-semibold mb-2">Mapping Notes</p>
                              <div className="space-y-2">
                                {ev.notes.map((note) => (
                                  <p key={note} className="text-sm text-muted-foreground">{note}</p>
                                ))}
                              </div>
                            </div>

                            <div className="rounded-xl border border-border bg-background/60 p-4">
                              <div className="flex flex-wrap items-start justify-between gap-3 mb-2">
                                <p className="text-sm font-semibold">Evidence Samples</p>
                                <div className="flex gap-2">
                                  <Button variant="outline" size="sm" asChild>
                                    <Link to="/dashboard/code-security">Code</Link>
                                  </Button>
                                  <Button variant="outline" size="sm" asChild>
                                    <Link to="/dashboard/network-security">Network</Link>
                                  </Button>
                                </div>
                              </div>

                              {ev.sample.length === 0 ? (
                                <p className="text-sm text-muted-foreground">No matched evidence samples yet for this item.</p>
                              ) : (
                                <div className="space-y-2">
                                  {ev.sample.map((row: DetailItem) => (
                                    <div key={row.id} className="flex items-start justify-between gap-4 rounded-lg border border-border/60 bg-card/40 px-3 py-2">
                                      <div>
                                        <p className="text-xs text-muted-foreground">{row.kind}</p>
                                        <p className="text-sm font-medium">{row.title}</p>
                                      </div>
                                      <div className="flex items-center gap-2">
                                        <SeverityBadge level={severityLabel(row.severity)} />
                                        {row.scanJob && (
                                          <Link className="text-xs text-primary hover:underline" to={`/dashboard/scans/${row.scanJob}`}>
                                            Scan
                                          </Link>
                                        )}
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          </>
                        );
                      })()
                    )}
                  </div>
                )}
              </ScrollArea>
            </DialogContent>
          </Dialog>
        </>
      )}
    </div>
  );
}
