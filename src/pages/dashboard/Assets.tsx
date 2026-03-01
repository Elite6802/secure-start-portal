import { useEffect, useState } from "react";
import { Link, useOutletContext } from "react-router-dom";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { EmptyState } from "@/components/dashboard/EmptyState";
import { RoleRestricted } from "@/components/dashboard/RoleRestricted";
import { ServiceRequestCard } from "@/components/dashboard/ServiceRequestCard";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Info } from "lucide-react";
import { PaginatedResponse, apiRequest, unwrapResults } from "@/lib/api";
import { Asset, ScanJob } from "@/lib/types";

export default function Assets() {
  const { accessRole } = useOutletContext<{ role: string; accessRole?: string | null }>();
  const restricted = accessRole ? accessRole !== "Security Lead" : true;
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeAsset, setActiveAsset] = useState<Asset | null>(null);
  const [scanJobs, setScanJobs] = useState<ScanJob[] | null>(null);
  const [loadingJobs, setLoadingJobs] = useState(false);
  const [jobsError, setJobsError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        if (!accessRole || restricted) {
          setLoading(false);
          setError(null);
          return;
        }
        setLoading(true);
        const data = await apiRequest<PaginatedResponse<Asset>>("/assets/");
        setAssets(unwrapResults<Asset>(data));
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Failed to load assets.");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [accessRole, restricted]);

  useEffect(() => {
    if (!activeAsset) return;
    if (scanJobs !== null) return; // cache once per page load

    let cancelled = false;
    const loadJobs = async () => {
      try {
        setLoadingJobs(true);
        setJobsError(null);
        const data = await apiRequest<PaginatedResponse<ScanJob>>("/scan-jobs/");
        if (!cancelled) setScanJobs(unwrapResults<ScanJob>(data));
      } catch (err: unknown) {
        if (!cancelled) setJobsError(err instanceof Error ? err.message : "Failed to load scan jobs.");
      } finally {
        if (!cancelled) setLoadingJobs(false);
      }
    };
    loadJobs();
    return () => {
      cancelled = true;
    };
  }, [activeAsset, scanJobs]);

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Protected Assets Inventory</h1>
      <p className="text-sm text-muted-foreground mb-8">Authoritative inventory of monitored infrastructure, applications, networks, and repositories.</p>

      <ServiceRequestCard
        title="Request Asset Coverage"
        description="Request baseline asset discovery or onboarding for a new environment. The platform team will validate scope and initiate coverage."
        serviceType="NETWORK_CONFIGURATION_SCAN"
        targetField="domain_url"
        allowedRoles={["Security Lead"]}
        accessRole={accessRole}
        helperText="Requests are reviewed by the platform security team."
        targetPlaceholder="Target (domain or IP/CIDR)"
        justificationPlaceholder="Describe the environment and coverage scope requested."
      />

      {!accessRole && <p className="text-sm text-muted-foreground mb-6">Loading access profile...</p>}
      {accessRole && restricted && (
        <RoleRestricted
          title="Asset inventory restricted"
          description="Protected asset inventory is available to Security Lead users for operational oversight."
        />
      )}
      {accessRole && !restricted && (
        <>
          {loading && <p className="text-sm text-muted-foreground mb-6">Loading assets...</p>}
          {error && <p className="text-sm text-destructive mb-6">{error}</p>}

          {assets.length === 0 && !loading ? (
            <EmptyState
              title="No assets onboarded yet"
              description="Once assets are connected, this inventory will list each application, network segment, and repository along with monitoring status and risk context. A complete inventory is the foundation for reliable coverage and audit readiness."
            />
          ) : (
            <div className="glass-card rounded-xl overflow-hidden">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Asset ID</TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>
                      <div className="flex items-center gap-2">
                        Risk Rating
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <button className="text-muted-foreground hover:text-foreground" aria-label="Risk rating tooltip">
                              <Info className="h-3.5 w-3.5" />
                            </button>
                          </TooltipTrigger>
                          <TooltipContent className="max-w-xs text-xs">
                            Risk reflects current exposure and remediation priority based on recent scan results.
                          </TooltipContent>
                        </Tooltip>
                      </div>
                    </TableHead>
                    <TableHead>Last Scan</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assets.map((asset) => (
                    <TableRow
                      key={asset.id}
                      className="cursor-pointer hover:bg-secondary/30"
                      onClick={() => setActiveAsset(asset)}
                    >
                      <TableCell className="font-mono text-xs">{asset.id}</TableCell>
                      <TableCell className="font-medium">{asset.name}</TableCell>
                      <TableCell className="text-muted-foreground text-sm">{asset.asset_type}</TableCell>
                      <TableCell><StatusBadge status={asset.last_scanned_at ? "Monitored" : "Scheduled"} /></TableCell>
                      <TableCell><SeverityBadge level={asset.risk_level === "moderate" ? "Medium" : asset.risk_level === "critical" ? "High" : "Low"} /></TableCell>
                      <TableCell className="text-sm text-muted-foreground">{asset.last_scanned_at || "â€”"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </>
      )}

      <Dialog open={activeAsset !== null} onOpenChange={(open) => (!open ? setActiveAsset(null) : null)}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>{activeAsset?.name ?? "Asset Detail"}</DialogTitle>
            <DialogDescription>Asset-level context and supporting scan history.</DialogDescription>
          </DialogHeader>

          <ScrollArea className="max-h-[70vh] pr-4">
            {activeAsset && (
              <div className="space-y-5">
                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <p className="text-sm font-semibold mb-2">Asset Profile</p>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div>
                      <p className="text-xs text-muted-foreground">Type</p>
                      <p className="text-sm font-medium">{activeAsset.asset_type}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Identifier</p>
                      <p className="text-sm font-medium break-all">{activeAsset.identifier}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Risk</p>
                      <div className="mt-1">
                        <SeverityBadge level={activeAsset.risk_level === "moderate" ? "Medium" : activeAsset.risk_level === "critical" ? "High" : "Low"} />
                      </div>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Last Scan</p>
                      <p className="text-sm font-medium">{activeAsset.last_scanned_at || "—"}</p>
                    </div>
                  </div>
                </div>

                <div className="rounded-xl border border-border bg-background/60 p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3 mb-2">
                    <p className="text-sm font-semibold">Recent Scan Jobs (This Asset)</p>
                    <Button variant="outline" size="sm" asChild>
                      <Link to="/dashboard/scans">Open Scans</Link>
                    </Button>
                  </div>

                  {jobsError && <p className="text-sm text-destructive mb-2">{jobsError}</p>}
                  {loadingJobs && <p className="text-sm text-muted-foreground">Loading scan jobs...</p>}

                  {scanJobs && (
                    <div className="space-y-2">
                      {scanJobs.filter((j) => j.asset === activeAsset.id).length === 0 ? (
                        <p className="text-sm text-muted-foreground">No scan jobs linked to this asset yet.</p>
                      ) : (
                        scanJobs
                          .filter((j) => j.asset === activeAsset.id)
                          .slice()
                          .sort((a, b) => (a.created_at < b.created_at ? 1 : -1))
                          .slice(0, 12)
                          .map((job) => (
                            <div key={job.id} className="flex items-start justify-between gap-4 rounded-lg border border-border/60 bg-card/40 px-3 py-2">
                              <div>
                                <p className="text-sm font-medium">{job.scan_type}</p>
                                <p className="text-xs text-muted-foreground">Status: {job.status}</p>
                              </div>
                              <Link className="text-xs text-primary hover:underline" to={`/dashboard/scans/${job.id}`}>
                                View
                              </Link>
                            </div>
                          ))
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}
          </ScrollArea>
        </DialogContent>
      </Dialog>
    </div>
  );
}
