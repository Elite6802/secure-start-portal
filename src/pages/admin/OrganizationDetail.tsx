import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { PaginatedResponse, apiRequest, unwrapResults } from "@/lib/api";
import { Organization, ServiceRequest, ScanJob, Incident, UserAccount, UserOrganization } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";

type UserWithMemberships = UserAccount & { memberships?: UserOrganization[] };
type OrgScanPolicy = {
  id: string;
  organization: string;
  ssrf_high_risk_enabled: boolean;
  ssrf_allow_metadata: boolean;
  ssrf_allowlist: unknown;
  inventory_expectations?: Record<string, number>;
  updated_at?: string;
};

  type OrgAsset = {
    id: string;
    organization: string;
    name: string;
    asset_type: string;
    identifier: string;
    owner_team?: string;
    owner_contact?: string;
    tags?: string[];
    high_risk_ssrf_authorized?: boolean;
    high_risk_ssrf_authorization_reference?: string;
    high_risk_ssrf_authorization_notes?: string;
  };

export default function OrganizationDetailAdmin() {
  const { id } = useParams();
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [users, setUsers] = useState<UserWithMemberships[]>([]);
  const [requests, setRequests] = useState<ServiceRequest[]>([]);
  const [scanJobs, setScanJobs] = useState<ScanJob[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [scanPolicy, setScanPolicy] = useState<OrgScanPolicy | null>(null);
  const [policyAllowlistDraft, setPolicyAllowlistDraft] = useState<string>("{}");
  const [policyExpectationsDraft, setPolicyExpectationsDraft] = useState<string>("{}");
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [assets, setAssets] = useState<OrgAsset[]>([]);
  const [savingAssetId, setSavingAssetId] = useState<string | null>(null);
  const [creatingAsset, setCreatingAsset] = useState(false);
  const [newAssetName, setNewAssetName] = useState("");
  const [newAssetType, setNewAssetType] = useState("web_app");
  const [newAssetIdentifier, setNewAssetIdentifier] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    const load = async () => {
      try {
        setLoading(true);
        setError(null);
        const [orgData, usersData, requestsData, jobsData, incidentsData, policyData, assetsData] = await Promise.all([
          apiRequest<Organization>(`/internal/organizations/${id}/`),
          apiRequest<PaginatedResponse<UserWithMemberships>>(`/internal/users/?organization=${id}`),
          apiRequest<PaginatedResponse<ServiceRequest>>(`/internal/service-requests/?organization=${id}`),
          apiRequest<PaginatedResponse<ScanJob>>(`/internal/scan-jobs/?organization=${id}`),
          apiRequest<PaginatedResponse<Incident>>(`/internal/incidents/?organization=${id}`),
          apiRequest<OrgScanPolicy>(`/internal/organizations/${id}/scan-policy/`),
          apiRequest<PaginatedResponse<OrgAsset>>(`/internal/assets/?organization=${id}`),
        ]);
        setOrganization(orgData);
        setUsers(unwrapResults<UserWithMemberships>(usersData));
        setRequests(
          unwrapResults<ServiceRequest>(requestsData).sort((a, b) => {
            const aTime = a.created_at ? new Date(a.created_at).getTime() : 0;
            const bTime = b.created_at ? new Date(b.created_at).getTime() : 0;
            return bTime - aTime;
          })
        );
        setScanJobs(unwrapResults<ScanJob>(jobsData));
        setIncidents(unwrapResults<Incident>(incidentsData));
        setScanPolicy(policyData);
        setPolicyAllowlistDraft(JSON.stringify(policyData?.ssrf_allowlist ?? {}, null, 2));
        setPolicyExpectationsDraft(JSON.stringify(policyData?.inventory_expectations ?? {}, null, 2));
        setAssets(unwrapResults<OrgAsset>(assetsData));
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Failed to load organization details.");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id]);

  const savePolicy = async () => {
    if (!id || !scanPolicy) return;
    setSavingPolicy(true);
    setError(null);
    try {
      const parsedAllowlist = JSON.parse(policyAllowlistDraft || "{}");
      const parsedExpectations = JSON.parse(policyExpectationsDraft || "{}");
      const updated = await apiRequest<OrgScanPolicy>(`/internal/organizations/${id}/scan-policy/`, {
        method: "POST",
        body: JSON.stringify({
          ssrf_high_risk_enabled: scanPolicy.ssrf_high_risk_enabled,
          ssrf_allow_metadata: scanPolicy.ssrf_allow_metadata,
          ssrf_allowlist: parsedAllowlist,
          inventory_expectations: parsedExpectations,
        }),
      });
      setScanPolicy(updated);
      setPolicyAllowlistDraft(JSON.stringify(updated?.ssrf_allowlist ?? {}, null, 2));
      setPolicyExpectationsDraft(JSON.stringify(updated?.inventory_expectations ?? {}, null, 2));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to save scan policy.");
    } finally {
      setSavingPolicy(false);
    }
  };

  const updateAsset = async (asset: OrgAsset) => {
    if (!id) return;
    setSavingAssetId(asset.id);
    setError(null);
    try {
      const updated = await apiRequest<OrgAsset>(`/internal/assets/${asset.id}/`, {
        method: "PATCH",
        body: JSON.stringify({
          high_risk_ssrf_authorized: Boolean(asset.high_risk_ssrf_authorized),
          high_risk_ssrf_authorization_reference: (asset.high_risk_ssrf_authorization_reference || "").trim(),
          high_risk_ssrf_authorization_notes: (asset.high_risk_ssrf_authorization_notes || "").trim(),
          owner_team: (asset.owner_team || "").trim(),
          owner_contact: (asset.owner_contact || "").trim(),
          tags: Array.isArray(asset.tags) ? asset.tags : [],
        }),
      });
      setAssets((prev) => prev.map((a) => (a.id === updated.id ? { ...a, ...updated } : a)));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to update asset authorization.");
    } finally {
      setSavingAssetId(null);
    }
  };

  const createAsset = async () => {
    if (!id) return;
    const name = newAssetName.trim();
    const identifier = newAssetIdentifier.trim();
    if (!name || !identifier) {
      setError("Asset name and identifier are required.");
      return;
    }
    setCreatingAsset(true);
    setError(null);
    try {
      const created = await apiRequest<OrgAsset>("/internal/assets/", {
        method: "POST",
        body: JSON.stringify({
          organization: id,
          name,
          asset_type: newAssetType,
          identifier,
          risk_level: "low",
        }),
      });
      setAssets((prev) => [created, ...prev]);
      setNewAssetName("");
      setNewAssetIdentifier("");
      setNewAssetType("web_app");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create asset.");
    } finally {
      setCreatingAsset(false);
    }
  };

  const userRows = useMemo(() => {
    return users.map((user) => {
      const membership = user.memberships?.find((m) => m.organization === id) || user.memberships?.[0];
      return {
        ...user,
        membershipOrganization: membership?.organization || "",
        membershipRole: membership?.role || "—",
        primary: membership?.is_primary ? "Primary" : "Secondary",
      };
    });
  }, [users, id]);

  if (!id) {
    return <p className="text-sm text-muted-foreground">Organization not found.</p>;
  }

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3 mb-6">
        <div>
          <h1 className="font-display text-2xl font-bold">Organization Detail</h1>
          <p className="text-sm text-muted-foreground">Tenant overview with linked users, scan requests, and operational activity.</p>
        </div>
        <Button variant="outline" asChild>
          <Link to="/admin/organizations">Back to Organizations</Link>
        </Button>
      </div>

      {loading && <p className="text-sm text-muted-foreground">Loading organization profile...</p>}
      {error && <p className="text-sm text-destructive mb-4">{error}</p>}

      {organization && (
        <div className="glass-card rounded-xl p-6 mb-8">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h2 className="font-display text-lg font-semibold">{organization.name}</h2>
              <p className="text-xs text-muted-foreground">Industry: {organization.industry || "—"}</p>
              <p className="text-xs text-muted-foreground">Domain: {organization.domain || "—"}</p>
            </div>
            <div className="flex gap-3">
              <Badge variant="outline" className="text-xs">{users.length} Users</Badge>
              <Badge variant="outline" className="text-xs">{requests.length} Requests</Badge>
              <Badge variant="outline" className="text-xs">{scanJobs.length} Scan Jobs</Badge>
              <Badge variant="outline" className="text-xs">{incidents.length} Incidents</Badge>
            </div>
          </div>
        </div>
      )}

      <div className="space-y-8">
        {scanPolicy && (
          <div className="glass-card rounded-xl p-6">
            <h2 className="font-display text-lg font-semibold mb-1">Scan Policy</h2>
            <p className="text-xs text-muted-foreground mb-4">
              Organization-level guardrails for advanced scan behaviors. High-risk SSRF validation is disabled by default and only runs for allowlisted targets.
            </p>

            <div className="grid gap-4 lg:grid-cols-2">
              <div className="space-y-3">
                <div className="flex items-start gap-3">
                  <Checkbox
                    id="ssrf_high_risk_enabled"
                    checked={scanPolicy.ssrf_high_risk_enabled}
                    onCheckedChange={(checked) =>
                      setScanPolicy((prev) =>
                        prev ? { ...prev, ssrf_high_risk_enabled: Boolean(checked) } : prev
                      )
                    }
                  />
                  <div className="grid gap-1">
                    <Label htmlFor="ssrf_high_risk_enabled" className="text-sm">
                      Enable high-risk SSRF validation
                    </Label>
                    <p className="text-xs text-muted-foreground">
                      Requires per-request ownership confirmation and an allowlist.
                    </p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <Checkbox
                    id="ssrf_allow_metadata"
                    checked={scanPolicy.ssrf_allow_metadata}
                    onCheckedChange={(checked) =>
                      setScanPolicy((prev) =>
                        prev ? { ...prev, ssrf_allow_metadata: Boolean(checked) } : prev
                      )
                    }
                  />
                  <div className="grid gap-1">
                    <Label htmlFor="ssrf_allow_metadata" className="text-sm">
                      Allow link-local / metadata IP targets
                    </Label>
                    <p className="text-xs text-muted-foreground">
                      Keep off unless you explicitly need SSRF validation against metadata endpoints in owned environments.
                    </p>
                  </div>
                </div>

                <Button onClick={savePolicy} disabled={savingPolicy}>
                  {savingPolicy ? "Saving..." : "Save Policy"}
                </Button>
              </div>

              <div>
                <Label className="text-xs font-medium text-muted-foreground">SSRF Allowlist (JSON)</Label>
                <Textarea
                  className="mt-2 font-mono text-xs min-h-[220px]"
                  value={policyAllowlistDraft}
                  onChange={(e) => setPolicyAllowlistDraft(e.target.value)}
                />
                <p className="mt-2 text-xs text-muted-foreground">
                  Expected shape: {"{\"domains\": [\"example.com\"], \"cidrs\": [\"10.10.0.0/16\"], \"urls\": [\"http://10.10.0.10:8080/health\"]}"}.
                  High-risk SSRF probes only use allowlisted URLs, and the scanned target must match domains/CIDRs.
                </p>
              </div>
              <div>
                <Label className="text-xs font-medium text-muted-foreground">Inventory Expectations (JSON)</Label>
                <Textarea
                  className="mt-2 font-mono text-xs min-h-[160px]"
                  value={policyExpectationsDraft}
                  onChange={(e) => setPolicyExpectationsDraft(e.target.value)}
                />
                <p className="mt-2 text-xs text-muted-foreground">
                  Optional expected counts used for inventory completeness scoring. Example: {"{\"domains\": 2, \"ip_ranges\": 1, \"apis\": 1, \"repos\": 1}"}.
                </p>
              </div>
            </div>
          </div>
        )}

        <div className="glass-card rounded-xl p-6">
          <h2 className="font-display text-lg font-semibold mb-1">Asset Authorization (High-Risk SSRF)</h2>
          <p className="text-xs text-muted-foreground mb-4">
            High-risk SSRF validation requires the scan target to be a registered asset explicitly authorized here, in addition to org allowlists and per-request attestation.
          </p>

          <div className="mb-5 rounded-lg border border-border bg-background/40 p-4">
            <p className="text-xs text-muted-foreground mb-3">Add an asset to the registry (needed if you want high-risk SSRF on a domain/URL that isn’t registered yet).</p>
            <div className="grid gap-3 lg:grid-cols-4">
              <div>
                <Label className="text-xs text-muted-foreground">Name</Label>
                <Input value={newAssetName} onChange={(e) => setNewAssetName(e.target.value)} placeholder="Acme Public Web" />
              </div>
              <div>
                <Label className="text-xs text-muted-foreground">Type</Label>
                <select
                  className="mt-2 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
                  value={newAssetType}
                  onChange={(e) => setNewAssetType(e.target.value)}
                >
                  <option value="domain">Domain</option>
                  <option value="web_app">Web Application</option>
                  <option value="api">API</option>
                  <option value="network_segment">Network Segment</option>
                  <option value="ip_range">IP Range</option>
                  <option value="cloud_resource">Cloud Resource</option>
                  <option value="code_repository">Code Repository</option>
                </select>
              </div>
              <div className="lg:col-span-2">
                <Label className="text-xs text-muted-foreground">Identifier</Label>
                <Input value={newAssetIdentifier} onChange={(e) => setNewAssetIdentifier(e.target.value)} placeholder="https://acme-finance.com" />
              </div>
            </div>
            <div className="mt-3">
              <Button variant="outline" onClick={createAsset} disabled={creatingAsset}>
                {creatingAsset ? "Creating..." : "Create Asset"}
              </Button>
            </div>
          </div>

          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Asset</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Identifier</TableHead>
                <TableHead>Team</TableHead>
                <TableHead>Owner</TableHead>
                <TableHead>Tags</TableHead>
                <TableHead>Authorized</TableHead>
                <TableHead>Reference</TableHead>
                <TableHead>Notes</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {assets.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={10} className="text-sm text-muted-foreground">
                    No assets found for this organization.
                  </TableCell>
                </TableRow>
              ) : (
                assets.map((asset) => (
                  <TableRow key={asset.id}>
                    <TableCell className="font-medium">{asset.name}</TableCell>
                    <TableCell className="text-muted-foreground text-sm">{asset.asset_type}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">{asset.identifier}</TableCell>
                    <TableCell>
                      <Input
                        value={asset.owner_team || ""}
                        onChange={(e) =>
                          setAssets((prev) => prev.map((a) => (a.id === asset.id ? { ...a, owner_team: e.target.value } : a)))
                        }
                        placeholder="AppSec / Payments"
                      />
                    </TableCell>
                    <TableCell>
                      <Input
                        value={asset.owner_contact || ""}
                        onChange={(e) =>
                          setAssets((prev) => prev.map((a) => (a.id === asset.id ? { ...a, owner_contact: e.target.value } : a)))
                        }
                        placeholder="owner@company.com"
                      />
                    </TableCell>
                    <TableCell>
                      <Input
                        value={(asset.tags || []).join(", ")}
                        onChange={(e) => {
                          const tags = e.target.value
                            .split(",")
                            .map((t) => t.trim())
                            .filter(Boolean)
                            .slice(0, 25);
                          setAssets((prev) => prev.map((a) => (a.id === asset.id ? { ...a, tags } : a)));
                        }}
                        placeholder="prod, customer-data, pci"
                      />
                    </TableCell>
                    <TableCell>
                      <Checkbox
                        checked={Boolean(asset.high_risk_ssrf_authorized)}
                        onCheckedChange={(checked) =>
                          setAssets((prev) =>
                            prev.map((a) =>
                              a.id === asset.id ? { ...a, high_risk_ssrf_authorized: Boolean(checked) } : a
                            )
                          )
                        }
                      />
                    </TableCell>
                    <TableCell>
                      <Input
                        value={asset.high_risk_ssrf_authorization_reference || ""}
                        onChange={(e) =>
                          setAssets((prev) =>
                            prev.map((a) =>
                              a.id === asset.id ? { ...a, high_risk_ssrf_authorization_reference: e.target.value } : a
                            )
                          )
                        }
                        placeholder="CHG-10492 / JIRA-SEC-118"
                      />
                    </TableCell>
                    <TableCell>
                      <Input
                        value={asset.high_risk_ssrf_authorization_notes || ""}
                        onChange={(e) =>
                          setAssets((prev) =>
                            prev.map((a) =>
                              a.id === asset.id ? { ...a, high_risk_ssrf_authorization_notes: e.target.value } : a
                            )
                          )
                        }
                        placeholder="window/contacts/constraints"
                      />
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="outline"
                        onClick={() => updateAsset(asset)}
                        disabled={savingAssetId === asset.id}
                      >
                        {savingAssetId === asset.id ? "Saving..." : "Save"}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>

        <div className="glass-card rounded-xl p-6">
          <h2 className="font-display text-lg font-semibold mb-4">Linked Users</h2>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Username</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Organization</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Primary</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {userRows.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-sm text-muted-foreground">No users linked to this organization.</TableCell>
                </TableRow>
              ) : (
                userRows.map((user) => (
                  <TableRow key={user.id}>
                    <TableCell className="font-medium">{user.username}</TableCell>
                    <TableCell className="text-muted-foreground">{user.email}</TableCell>
                    <TableCell className="text-muted-foreground">{organization?.name || "—"}</TableCell>
                    <TableCell className="text-muted-foreground">{user.membershipRole}</TableCell>
                    <TableCell className="text-muted-foreground">{user.primary}</TableCell>
                    <TableCell>
                      {user.is_active ? (
                        <Badge variant="secondary" className="text-xs">Active</Badge>
                      ) : (
                        <Badge variant="destructive" className="text-xs">Inactive</Badge>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>

        <div className="glass-card rounded-xl p-6">
          <h2 className="font-display text-lg font-semibold mb-4">Service Requests</h2>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Service Type</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Requested</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {requests.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-sm text-muted-foreground">No service requests submitted yet.</TableCell>
                </TableRow>
              ) : (
                requests.map((request) => (
                  <TableRow key={request.id}>
                    <TableCell className="text-sm">{request.service_type}</TableCell>
                    <TableCell className="text-muted-foreground">{request.repository_url || request.domain_url || request.ip_cidr || request.asset || "—"}</TableCell>
                    <TableCell><Badge variant="outline" className="text-xs">{request.status}</Badge></TableCell>
                    <TableCell className="text-xs text-muted-foreground">{request.created_at?.slice(0, 10)}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          <div className="glass-card rounded-xl p-6">
            <h2 className="font-display text-lg font-semibold mb-4">Scan Jobs</h2>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Type</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scanJobs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3} className="text-sm text-muted-foreground">No scan jobs recorded.</TableCell>
                  </TableRow>
                ) : (
                  scanJobs.map((job) => (
                    <TableRow key={job.id}>
                      <TableCell className="text-sm">{job.scan_type}</TableCell>
                      <TableCell><Badge variant="outline" className="text-xs">{job.status}</Badge></TableCell>
                      <TableCell className="text-xs text-muted-foreground">{job.created_at?.slice(0, 10)}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          <div className="glass-card rounded-xl p-6">
            <h2 className="font-display text-lg font-semibold mb-4">Incidents</h2>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Severity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Detected</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {incidents.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3} className="text-sm text-muted-foreground">No incidents recorded.</TableCell>
                  </TableRow>
                ) : (
                  incidents.map((incident) => (
                    <TableRow key={incident.id}>
                      <TableCell className="text-sm">{incident.severity}</TableCell>
                      <TableCell><Badge variant="outline" className="text-xs">{incident.status}</Badge></TableCell>
                      <TableCell className="text-xs text-muted-foreground">{incident.detected_at?.slice(0, 10)}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </div>
      </div>
    </div>
  );
}
