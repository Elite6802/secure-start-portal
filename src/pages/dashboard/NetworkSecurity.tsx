import { useEffect, useMemo, useState } from "react";
import { Link, useOutletContext, useSearchParams } from "react-router-dom";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { RoleRestricted } from "@/components/dashboard/RoleRestricted";
import { ServiceRequestCard } from "@/components/dashboard/ServiceRequestCard";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Shield, Network } from "lucide-react";
import { PaginatedResponse, apiRequest, unwrapResults } from "@/lib/api";
import { NetworkAsset, NetworkFinding } from "@/lib/types";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";

function parseEndpoint(raw: string | null): { host: string; port: number } | null {
  if (!raw) return null;
  const value = raw.trim();
  if (!value) return null;
  const idx = value.lastIndexOf(":");
  if (idx <= 0 || idx === value.length - 1) return null;
  const host = value.slice(0, idx).trim();
  const portRaw = value.slice(idx + 1).trim();
  const port = Number(portRaw);
  if (!host || !Number.isFinite(port) || port <= 0) return null;
  return { host, port };
}

function findingEndpointLabel(finding: NetworkFinding): string {
  const ev = finding.evidence || {};
  const host = String((ev as Record<string, unknown>).host ?? (ev as Record<string, unknown>).ip ?? (ev as Record<string, unknown>).hostname ?? "").trim();
  const port = Number((ev as Record<string, unknown>).port ?? (ev as Record<string, unknown>).service_port ?? 0);
  if (host && Number.isFinite(port) && port > 0) return `${host}:${port}`;
  const testedUrl = String((ev as Record<string, unknown>).tested_url ?? "").trim();
  if (testedUrl) return testedUrl;
  return "—";
}

export default function NetworkSecurity() {
  const { accessRole } = useOutletContext<{ role: string; accessRole?: string | null }>();
  const restricted = accessRole ? accessRole !== "Security Lead" : true;
  const [searchParams, setSearchParams] = useSearchParams();
  const endpointParam = searchParams.get("endpoint");
  const endpointFilter = useMemo(() => parseEndpoint(endpointParam), [endpointParam]);
  const [networkAssets, setNetworkAssets] = useState<NetworkAsset[]>([]);
  const [networkFindings, setNetworkFindings] = useState<NetworkFinding[]>([]);
  const [activeKpi, setActiveKpi] = useState<null | "internet_facing_assets" | "critical_ports_exposed" | "tls_findings">(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        if (!accessRole || restricted) {
          setLoading(false);
          setError(null);
          return;
        }
        setLoading(true);
        const [assetsData, findingsData] = await Promise.all([
          apiRequest<PaginatedResponse<NetworkAsset>>("/network-assets/"),
          apiRequest<PaginatedResponse<NetworkFinding>>("/network-findings/"),
        ]);
        setNetworkAssets(unwrapResults<NetworkAsset>(assetsData));
        setNetworkFindings(unwrapResults<NetworkFinding>(findingsData));
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Failed to load network data.");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [accessRole, restricted]);

  const externalExposure = useMemo(() => {
    const internetFacingAssets = networkAssets.filter((asset) => asset.network_type === "external").length;
    const criticalPortsOpen = networkFindings.filter(
      (finding) => finding.finding_type === "exposed_service" && (finding.severity === "critical" || finding.severity === "high"),
    ).length;
    const tlsFindings = networkFindings.filter((finding) => finding.finding_type === "misconfiguration").length;
    return { internetFacingAssets, criticalPortsOpen, tlsFindings };
  }, [networkAssets, networkFindings]);

  const openServices = useMemo(() => {
    const groups: Record<string, { count: number; risk: string }> = {};
    networkFindings
      .filter((finding) => finding.finding_type === "exposed_service")
      .forEach((finding) => {
        const key = finding.summary || "Exposed Service";
        if (!groups[key]) {
          groups[key] = { count: 0, risk: finding.severity };
        }
        groups[key].count += 1;
      });
    return Object.entries(groups).map(([service, meta]) => ({
      service,
      count: meta.count,
      risk: meta.risk === "moderate" ? "Medium" : meta.risk === "high" ? "High" : meta.risk === "critical" ? "Critical" : "Low",
    }));
  }, [networkFindings]);

  const segmentationRisk = useMemo(() => {
    const count = networkFindings.filter((finding) => finding.finding_type === "segmentation_risk").length;
    const score = Math.min(100, 40 + count * 15);
    return {
      score,
      status: count > 3 ? "High" : count > 0 ? "Moderate" : "Low",
      summary: count > 0 ? "Segmentation findings require review and hardening." : "No segmentation findings detected yet.",
    };
  }, [networkFindings]);

  const filteredFindings = useMemo(() => {
    if (!endpointFilter) return networkFindings;
    const { host, port } = endpointFilter;
    return networkFindings.filter((finding) => {
      const ev = finding.evidence || {};
      const evAny = ev as Record<string, unknown>;
      const evHost = String(evAny.host ?? evAny.ip ?? evAny.hostname ?? "").trim();
      const evPort = Number(evAny.port ?? evAny.service_port ?? 0);
      if (evHost && Number.isFinite(evPort) && evPort > 0) {
        return evHost === host && evPort === port;
      }
      const summary = (finding.summary || "").toLowerCase();
      return summary.includes(host.toLowerCase()) && summary.includes(String(port));
    });
  }, [networkFindings, endpointFilter]);

  const clearEndpointFilter = () => {
    const next = new URLSearchParams(searchParams);
    next.delete("endpoint");
    setSearchParams(next);
  };

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Network Security Visibility</h1>
      <p className="text-sm text-muted-foreground mb-8">Phase 1 visibility for external exposure, service inventory, and segmentation posture.</p>

      <ServiceRequestCard
        title="Request Network Exposure Review"
        description="Submit a network scope for external exposure and segmentation review. The platform team will validate access and return findings."
        serviceType="NETWORK_CONFIGURATION_SCAN"
        targetField="domain_url"
        allowedRoles={["Security Lead"]}
        accessRole={accessRole}
        helperText="Requests are reviewed by the platform security team."
        targetPlaceholder="Target (CIDR range, IP block, environment)"
        justificationPlaceholder="Provide IP ranges, business context, and expected testing window."
      />

      {!accessRole && <p className="text-sm text-muted-foreground mb-6">Loading access profile...</p>}
      {accessRole && restricted && (
        <RoleRestricted
          title="Network security view restricted"
          description="Network exposure details are limited to Security Lead users. Switch roles to review network posture."
        />
      )}
      {accessRole && !restricted && (
        <>
          {loading && <p className="text-sm text-muted-foreground mb-6">Loading network visibility...</p>}
          {error && <p className="text-sm text-destructive mb-6">{error}</p>}

          <div className="grid gap-4 md:grid-cols-3">
            <button
              type="button"
              onClick={() => setActiveKpi("internet_facing_assets")}
              className="glass-card rounded-xl p-5 text-left transition hover:border-primary/30 focus:outline-none focus:ring-2 focus:ring-primary/30"
            >
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-medium text-muted-foreground">Internet-Facing Assets</span>
                <Network className="h-4 w-4 text-primary" />
              </div>
              <p className="font-display text-2xl font-bold">{externalExposure.internetFacingAssets}</p>
              <p className="mt-2 text-[11px] text-muted-foreground">View details</p>
            </button>
            <button
              type="button"
              onClick={() => setActiveKpi("critical_ports_exposed")}
              className="glass-card rounded-xl p-5 text-left transition hover:border-primary/30 focus:outline-none focus:ring-2 focus:ring-primary/30"
            >
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-medium text-muted-foreground">Critical Ports Exposed</span>
                <Shield className="h-4 w-4 text-warning" />
              </div>
              <p className="font-display text-2xl font-bold">{externalExposure.criticalPortsOpen}</p>
              <p className="mt-2 text-[11px] text-muted-foreground">View details</p>
            </button>
            <button
              type="button"
              onClick={() => setActiveKpi("tls_findings")}
              className="glass-card rounded-xl p-5 text-left transition hover:border-primary/30 focus:outline-none focus:ring-2 focus:ring-primary/30"
            >
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-medium text-muted-foreground">TLS Policy Findings</span>
                <Shield className="h-4 w-4 text-primary" />
              </div>
              <p className="font-display text-2xl font-bold">{externalExposure.tlsFindings}</p>
              <p className="mt-2 text-[11px] text-muted-foreground">View details</p>
            </button>
          </div>

          <div className="mt-6 grid gap-6 lg:grid-cols-2">
            <div className="glass-card rounded-xl p-6">
              <h2 className="font-display text-lg font-semibold mb-4">Open Services Summary</h2>
              <div className="space-y-3">
                {openServices.length === 0 ? (
                  <div className="text-sm text-muted-foreground">No exposed services reported.</div>
                ) : openServices.map((service) => (
                  <div key={service.service} className="flex items-center justify-between rounded-lg bg-secondary/60 px-4 py-3">
                    <div>
                      <p className="text-sm font-medium">{service.service}</p>
                      <p className="text-xs text-muted-foreground">{service.count} detected endpoints</p>
                    </div>
                    <SeverityBadge level={service.risk} />
                  </div>
                ))}
              </div>
            </div>

            <div className="glass-card rounded-xl p-6">
              <h2 className="font-display text-lg font-semibold mb-4">Segmentation Risk Indicator</h2>
              <div className="mb-3 flex items-center justify-between">
                <span className="text-xs text-muted-foreground">Risk Score</span>
                <span className="text-sm font-semibold">{segmentationRisk.score}/100</span>
              </div>
              <Progress value={segmentationRisk.score} />
              <div className="mt-4 rounded-lg border border-border/60 bg-secondary/40 p-4">
                <p className="text-xs font-semibold text-muted-foreground">Status: {segmentationRisk.status}</p>
                <p className="text-sm text-muted-foreground mt-1">{segmentationRisk.summary}</p>
              </div>
            </div>
          </div>

          <div className="mt-6 glass-card rounded-xl p-6">
            <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
              <div>
                <h2 className="font-display text-lg font-semibold">Network Findings</h2>
                <p className="text-xs text-muted-foreground">
                  {endpointFilter ? "Filtered by endpoint." : "All recorded network findings."}
                </p>
              </div>
              {endpointFilter && (
                <div className="flex items-center gap-2">
                  <span className="rounded-full border border-border bg-background/60 px-3 py-1 text-xs text-muted-foreground">
                    {endpointFilter.host}:{endpointFilter.port}
                  </span>
                  <Button variant="outline" size="sm" onClick={clearEndpointFilter}>
                    Clear
                  </Button>
                </div>
              )}
            </div>

            {endpointParam && !endpointFilter && (
              <p className="text-sm text-destructive mb-4">
                Invalid endpoint filter. Expected format like <span className="font-mono">host:port</span>.
              </p>
            )}

            {filteredFindings.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                {endpointFilter ? "No findings matched this endpoint yet." : "No network findings recorded yet."}
              </p>
            ) : (
              <div className="rounded-xl overflow-hidden border border-border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Severity</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Endpoint</TableHead>
                      <TableHead>Summary</TableHead>
                      <TableHead>Scan</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredFindings
                      .slice()
                      .sort((a, b) => (a.created_at < b.created_at ? 1 : -1))
                      .slice(0, 50)
                      .map((finding) => (
                        <TableRow key={finding.id}>
                          <TableCell>
                            <SeverityBadge
                              level={
                                finding.severity === "moderate"
                                  ? "Medium"
                                  : finding.severity === "high"
                                  ? "High"
                                  : finding.severity === "critical"
                                  ? "Critical"
                                  : "Low"
                              }
                            />
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground">{finding.finding_type}</TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">{findingEndpointLabel(finding)}</TableCell>
                          <TableCell className="text-sm">
                            <p className="font-medium">{finding.summary}</p>
                            {finding.recommendation && (
                              <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{finding.recommendation}</p>
                            )}
                          </TableCell>
                          <TableCell className="text-sm">
                            {finding.scan_job ? (
                              <Link className="text-primary hover:underline" to={`/dashboard/scans/${finding.scan_job}`}>
                                View
                              </Link>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                  </TableBody>
                </Table>
              </div>
            )}

            <p className="mt-4 text-xs text-muted-foreground">
              Tip: click an endpoint in <Link className="text-primary hover:underline" to="/dashboard/analyst">Analyst Workspace</Link> → Exposure Hotspots to jump here filtered.
            </p>
          </div>

          <Dialog open={activeKpi !== null} onOpenChange={(open) => (!open ? setActiveKpi(null) : null)}>
            <DialogContent className="max-w-3xl">
              <DialogHeader>
                <DialogTitle>
                  {activeKpi === "internet_facing_assets" && "Internet-Facing Assets"}
                  {activeKpi === "critical_ports_exposed" && "Critical Ports Exposed"}
                  {activeKpi === "tls_findings" && "TLS Policy Findings"}
                </DialogTitle>
                <DialogDescription>Drill-down context derived from the network scans executed for this tenant.</DialogDescription>
              </DialogHeader>

              <ScrollArea className="max-h-[70vh] pr-4">
                {activeKpi === "internet_facing_assets" && (
                  <div className="space-y-4">
                    <div className="rounded-xl border border-border bg-background/60 p-4">
                      <p className="text-sm font-semibold mb-1">What This Measures</p>
                      <p className="text-sm text-muted-foreground">
                        Count of network assets marked as external/internet-facing in the inventory. Validate exposure and ensure segmentation controls are in place.
                      </p>
                    </div>
                    <div className="rounded-xl border border-border bg-background/60 p-4">
                      <p className="text-xs text-muted-foreground">Current Count</p>
                      <p className="mt-1 text-2xl font-semibold">{externalExposure.internetFacingAssets}</p>
                    </div>
                    <div className="rounded-xl border border-border bg-background/60 p-4">
                      <p className="text-sm font-semibold mb-2">Sample Assets</p>
                      {networkAssets.filter((a) => a.network_type === "external").length === 0 ? (
                        <p className="text-sm text-muted-foreground">No external assets currently recorded.</p>
                      ) : (
                        <div className="space-y-2">
                          {networkAssets
                            .filter((a) => a.network_type === "external")
                            .slice(0, 12)
                            .map((a) => (
                              <div key={a.id} className="rounded-lg border border-border/60 bg-card/40 px-3 py-2">
                                <p className="text-sm font-medium">{a.asset}</p>
                                <p className="text-xs text-muted-foreground">Network type: external</p>
                              </div>
                            ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {activeKpi === "critical_ports_exposed" && (
                  <div className="space-y-4">
                    <div className="rounded-xl border border-border bg-background/60 p-4">
                      <p className="text-sm font-semibold mb-1">What This Measures</p>
                      <p className="text-sm text-muted-foreground">
                        Count of exposed service findings where severity is high/critical. These are typically the highest priority to remediate.
                      </p>
                    </div>
                    <div className="rounded-xl border border-border bg-background/60 p-4">
                      <p className="text-xs text-muted-foreground">Current Count</p>
                      <p className="mt-1 text-2xl font-semibold">{externalExposure.criticalPortsOpen}</p>
                    </div>
                    <div className="rounded-xl border border-border bg-background/60 p-4">
                      <p className="text-sm font-semibold mb-2">Sample Findings</p>
                      {networkFindings.filter((f) => f.finding_type === "exposed_service" && (f.severity === "critical" || f.severity === "high")).length === 0 ? (
                        <p className="text-sm text-muted-foreground">No high/critical exposed services recorded.</p>
                      ) : (
                        <div className="space-y-2">
                          {networkFindings
                            .filter((f) => f.finding_type === "exposed_service" && (f.severity === "critical" || f.severity === "high"))
                            .slice(0, 12)
                            .map((f) => (
                              <div key={f.id} className="flex items-start justify-between gap-4 rounded-lg border border-border/60 bg-card/40 px-3 py-2">
                                <div>
                                  <p className="text-sm font-medium">{f.summary}</p>
                                  <p className="text-xs text-muted-foreground">{findingEndpointLabel(f)}</p>
                                </div>
                                {f.scan_job ? (
                                  <Link className="text-xs text-primary hover:underline" to={`/dashboard/scans/${f.scan_job}`}>
                                    Scan
                                  </Link>
                                ) : (
                                  <span className="text-xs text-muted-foreground">—</span>
                                )}
                              </div>
                            ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {activeKpi === "tls_findings" && (
                  <div className="space-y-4">
                    <div className="rounded-xl border border-border bg-background/60 p-4">
                      <p className="text-sm font-semibold mb-1">What This Measures</p>
                      <p className="text-sm text-muted-foreground">
                        Count of TLS-related misconfiguration signals. Review for weak ciphers, missing HSTS, certificate issues, and inconsistent HTTPS enforcement.
                      </p>
                    </div>
                    <div className="rounded-xl border border-border bg-background/60 p-4">
                      <p className="text-xs text-muted-foreground">Current Count</p>
                      <p className="mt-1 text-2xl font-semibold">{externalExposure.tlsFindings}</p>
                    </div>
                    <div className="rounded-xl border border-border bg-background/60 p-4">
                      <p className="text-sm font-semibold mb-2">Sample Findings</p>
                      {networkFindings.filter((f) => f.finding_type === "misconfiguration").length === 0 ? (
                        <p className="text-sm text-muted-foreground">No TLS/misconfiguration findings recorded.</p>
                      ) : (
                        <div className="space-y-2">
                          {networkFindings
                            .filter((f) => f.finding_type === "misconfiguration")
                            .slice(0, 12)
                            .map((f) => (
                              <div key={f.id} className="flex items-start justify-between gap-4 rounded-lg border border-border/60 bg-card/40 px-3 py-2">
                                <div>
                                  <p className="text-sm font-medium">{f.summary}</p>
                                  <p className="text-xs text-muted-foreground">{findingEndpointLabel(f)}</p>
                                </div>
                                {f.scan_job ? (
                                  <Link className="text-xs text-primary hover:underline" to={`/dashboard/scans/${f.scan_job}`}>
                                    Scan
                                  </Link>
                                ) : (
                                  <span className="text-xs text-muted-foreground">—</span>
                                )}
                              </div>
                            ))}
                        </div>
                      )}
                    </div>
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
