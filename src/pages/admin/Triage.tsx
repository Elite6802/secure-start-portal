import { useEffect, useMemo, useState } from "react";
import { apiRequest } from "@/lib/api";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { AlertTriangle, CheckCircle2, Clock, Filter, RefreshCw } from "lucide-react";

type GroupBy = "team" | "owner" | "tag";
type TriageStatus = "open" | "suppressed" | "accepted_risk" | "resolved" | "all";

type FixByOwnerRow = {
  group_key: string;
  open_total: number;
  overdue_total: number;
  by_severity: { critical: number; high: number; moderate: number; low: number };
  sample: Array<{ kind: string; id: string; title: string; severity: string; asset_name: string; age_days: number; overdue: boolean }>;
};

type FixByOwner = {
  generated_at: string;
  group_by: GroupBy;
  count: number;
  results: FixByOwnerRow[];
};

type SlaOverview = {
  generated_at: string;
  window_days: number;
  thresholds_days: Record<string, number>;
  open_total: number;
  overdue_total: number;
  by_severity: Record<string, { total_open: number; overdue: number; age_buckets: Record<string, number> }>;
  mttr_days: { overall: number | null; code: number | null; network: number | null; cloud: number | null };
};

type FindingRow = {
  kind: "code" | "network" | "cloud";
  id: string;
  title: string;
  severity: "critical" | "high" | "moderate" | "low";
  status: TriageStatus;
  asset_name: string;
  owner_team: string;
  owner_contact: string;
  tags: string[];
  age_days: number;
  sla_days: number;
  overdue: boolean;
  disposition?: { status: string; expires_at?: string | null; justification?: string | null };
};

export default function AdminTriage() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [groupBy, setGroupBy] = useState<GroupBy>("team");
  const [board, setBoard] = useState<FixByOwner | null>(null);
  const [sla, setSla] = useState<SlaOverview | null>(null);

  const [activeGroupKey, setActiveGroupKey] = useState<string | null>(null);
  const [activeStatus, setActiveStatus] = useState<TriageStatus>("open");
  const [groupFindings, setGroupFindings] = useState<FindingRow[]>([]);
  const [findingLoading, setFindingLoading] = useState(false);

  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const selectedItems = useMemo(
    () => groupFindings.filter((f) => selected[`${f.kind}:${f.id}`]).map((f) => ({ kind: f.kind, id: f.id })),
    [groupFindings, selected]
  );

  const [bulkAction, setBulkAction] = useState<"accept_risk" | "suppress" | "resolve" | "retest">("accept_risk");
  const [justification, setJustification] = useState("");
  const [expiresAt, setExpiresAt] = useState<string>("");
  const [bulkRunning, setBulkRunning] = useState(false);

  const loadAll = async () => {
    setLoading(true);
    setError(null);
    try {
      const [b, s] = await Promise.all([
        apiRequest<FixByOwner>(`/internal/triage/fix-by-owner/?group_by=${groupBy}`),
        apiRequest<SlaOverview>("/internal/triage/sla/overview/"),
      ]);
      setBoard(b);
      setSla(s);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load triage data.");
    } finally {
      setLoading(false);
    }
  };

  const loadGroupFindings = async (key: string, status: TriageStatus) => {
    setFindingLoading(true);
    setError(null);
    try {
      const resp = await apiRequest<{ results: FindingRow[] }>(
        `/internal/triage/findings/?group_by=${groupBy}&group_key=${encodeURIComponent(key)}&status=${status}`
      );
      setGroupFindings(resp.results || []);
      setSelected({});
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load group findings.");
      setGroupFindings([]);
      setSelected({});
    } finally {
      setFindingLoading(false);
    }
  };

  useEffect(() => {
    loadAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groupBy]);

  const sevTone = (sev: string) => {
    if (sev === "critical") return "border-rose-500/30 bg-rose-500/10 text-rose-700";
    if (sev === "high") return "border-amber-500/30 bg-amber-500/10 text-amber-700";
    if (sev === "moderate") return "border-sky-500/30 bg-sky-500/10 text-sky-700";
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-700";
  };

  const statusTone = (st: string) => {
    if (st === "open") return "border-amber-500/30 bg-amber-500/10 text-amber-700";
    if (st === "resolved") return "border-emerald-500/30 bg-emerald-500/10 text-emerald-700";
    if (st === "suppressed") return "border-slate-500/30 bg-slate-500/10 text-slate-700";
    if (st === "accepted_risk") return "border-violet-500/30 bg-violet-500/10 text-violet-700";
    return "border-border bg-background/40 text-muted-foreground";
  };

  const runBulk = async () => {
    if (selectedItems.length === 0) {
      setError("Select at least one finding first.");
      return;
    }
    if ((bulkAction === "accept_risk" || bulkAction === "suppress") && !justification.trim()) {
      setError("Justification is required for Accept Risk and Suppress.");
      return;
    }
    if (bulkAction === "suppress" && !expiresAt) {
      setError("Expiry is required for Suppress.");
      return;
    }
    setBulkRunning(true);
    setError(null);
    try {
      await apiRequest("/internal/triage/bulk-action/", {
        method: "POST",
        body: JSON.stringify({
          action: bulkAction,
          items: selectedItems,
          justification,
          expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
        }),
      });
      if (activeGroupKey) {
        await loadGroupFindings(activeGroupKey, activeStatus);
      }
      await loadAll();
      setJustification("");
      setExpiresAt("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Bulk action failed.");
    } finally {
      setBulkRunning(false);
    }
  };

  const openTotal = sla?.open_total ?? 0;
  const overdueTotal = sla?.overdue_total ?? 0;
  const mttr = sla?.mttr_days?.overall ?? null;

  return (
    <div>
      <div className="flex items-start justify-between gap-3 mb-6">
        <div>
          <h1 className="font-display text-2xl font-bold mb-1">Triage & Remediation</h1>
          <p className="text-sm text-muted-foreground">
            Fix-by-owner routing, SLA tracking, and safe bulk actions (accept risk, suppress with expiry, re-test, resolve).
          </p>
        </div>
        <Button variant="outline" onClick={loadAll} disabled={loading}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </div>

      {error && <div className="mb-4 text-sm text-destructive">{error}</div>}

      {loading ? (
        <p className="text-sm text-muted-foreground">Loading triage data...</p>
      ) : (
        <>
          <div className="mb-6 grid gap-4 lg:grid-cols-3">
            <div className="glass-card rounded-xl p-5">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium text-muted-foreground">Open Findings</span>
                <AlertTriangle className="h-4 w-4 text-primary" />
              </div>
              <div className="font-display text-3xl font-bold">{openTotal}</div>
              <div className="mt-2 text-xs text-muted-foreground">Effective open = excludes suppressed + accepted risk + resolved.</div>
            </div>
            <div className="glass-card rounded-xl p-5">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium text-muted-foreground">Overdue (SLA)</span>
                <Clock className="h-4 w-4 text-primary" />
              </div>
              <div className={`font-display text-3xl font-bold ${overdueTotal > 0 ? "text-rose-700" : ""}`}>{overdueTotal}</div>
              <div className="mt-2 text-xs text-muted-foreground">SLA thresholds: Critical 7d, High 14d, Moderate 30d, Low 90d (configurable).</div>
            </div>
            <div className="glass-card rounded-xl p-5">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium text-muted-foreground">MTTR (days)</span>
                <CheckCircle2 className="h-4 w-4 text-primary" />
              </div>
              <div className="font-display text-3xl font-bold">{typeof mttr === "number" ? mttr : "—"}</div>
              <div className="mt-2 text-xs text-muted-foreground">Mean time to resolve (last {sla?.window_days ?? 90} days), best-effort.</div>
            </div>
          </div>

          <div className="mb-4 flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Filter className="h-4 w-4" />
              Group by:
            </div>
            <div className="w-64">
              <Select value={groupBy} onValueChange={(v) => setGroupBy(v as GroupBy)}>
                <SelectTrigger>
                  <SelectValue placeholder="Group by" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="team">Team</SelectItem>
                  <SelectItem value="owner">Owner</SelectItem>
                  <SelectItem value="tag">Tag</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="glass-card rounded-xl p-4">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{groupBy === "team" ? "Team" : groupBy === "owner" ? "Owner" : "Tag"}</TableHead>
                  <TableHead>Open</TableHead>
                  <TableHead>Overdue</TableHead>
                  <TableHead>By Severity</TableHead>
                  <TableHead>Sample</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {(board?.results || []).map((row) => (
                  <TableRow key={row.group_key}>
                    <TableCell className="font-medium">{row.group_key}</TableCell>
                    <TableCell className="text-sm">{row.open_total}</TableCell>
                    <TableCell className={`text-sm ${row.overdue_total > 0 ? "text-rose-700" : "text-muted-foreground"}`}>{row.overdue_total}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      <span className={`mr-2 inline-flex items-center rounded-full border px-2 py-1 ${sevTone("critical")}`}>C {row.by_severity.critical}</span>
                      <span className={`mr-2 inline-flex items-center rounded-full border px-2 py-1 ${sevTone("high")}`}>H {row.by_severity.high}</span>
                      <span className={`mr-2 inline-flex items-center rounded-full border px-2 py-1 ${sevTone("moderate")}`}>M {row.by_severity.moderate}</span>
                      <span className={`inline-flex items-center rounded-full border px-2 py-1 ${sevTone("low")}`}>L {row.by_severity.low}</span>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {(row.sample || []).slice(0, 2).map((s) => (
                        <div key={`${s.kind}:${s.id}`} className="truncate">
                          {s.severity.toUpperCase()} · {s.asset_name} · {s.title}
                        </div>
                      ))}
                      {(row.sample || []).length === 0 && "—"}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        size="sm"
                        onClick={async () => {
                          setActiveGroupKey(row.group_key);
                          setActiveStatus("open");
                          await loadGroupFindings(row.group_key, "open");
                        }}
                      >
                        Open
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
                {(!board?.results || board.results.length === 0) && (
                  <TableRow>
                    <TableCell colSpan={6} className="text-sm text-muted-foreground">
                      No groups found yet.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>

          <Dialog
            open={activeGroupKey !== null}
            onOpenChange={(open) => {
              if (!open) {
                setActiveGroupKey(null);
                setGroupFindings([]);
                setSelected({});
              }
            }}
          >
            <DialogContent className="max-w-6xl">
              <DialogHeader>
                <DialogTitle>Findings for: {activeGroupKey}</DialogTitle>
                <DialogDescription>
                  Select findings, then apply bulk actions. Suppression requires justification + expiry.
                </DialogDescription>
              </DialogHeader>

              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="w-56">
                  <Select
                    value={activeStatus}
                    onValueChange={async (v) => {
                      const st = v as TriageStatus;
                      setActiveStatus(st);
                      if (activeGroupKey) await loadGroupFindings(activeGroupKey, st);
                    }}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Status" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="open">Open</SelectItem>
                      <SelectItem value="suppressed">Suppressed</SelectItem>
                      <SelectItem value="accepted_risk">Accepted Risk</SelectItem>
                      <SelectItem value="resolved">Resolved</SelectItem>
                      <SelectItem value="all">All</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <div className="text-xs text-muted-foreground mr-2">
                    Selected: <span className="font-semibold">{selectedItems.length}</span>
                  </div>
                  <Select value={bulkAction} onValueChange={(v) => setBulkAction(v as any)}>
                    <SelectTrigger className="w-44">
                      <SelectValue placeholder="Action" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="accept_risk">Accept Risk</SelectItem>
                      <SelectItem value="suppress">Suppress</SelectItem>
                      <SelectItem value="retest">Re-test</SelectItem>
                      <SelectItem value="resolve">Mark Resolved</SelectItem>
                    </SelectContent>
                  </Select>
                  <input
                    className="h-9 w-72 rounded-md border border-border bg-background px-3 text-sm"
                    placeholder="Justification (required for Accept Risk / Suppress)"
                    value={justification}
                    onChange={(e) => setJustification(e.target.value)}
                  />
                  <input
                    className="h-9 w-56 rounded-md border border-border bg-background px-3 text-sm"
                    type="datetime-local"
                    value={expiresAt}
                    onChange={(e) => setExpiresAt(e.target.value)}
                    title="Expiry (required for Suppress)"
                  />
                  <Button onClick={runBulk} disabled={bulkRunning || findingLoading}>
                    {bulkRunning ? "Applying..." : "Apply"}
                  </Button>
                </div>
              </div>

              <div className="mt-3 rounded-xl border border-border bg-background/40">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-10" />
                      <TableHead>Severity</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Asset</TableHead>
                      <TableHead>Title</TableHead>
                      <TableHead>Age</TableHead>
                      <TableHead>Owner</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {findingLoading ? (
                      <TableRow>
                        <TableCell colSpan={7} className="text-sm text-muted-foreground">
                          Loading findings...
                        </TableCell>
                      </TableRow>
                    ) : (
                      groupFindings.map((f) => {
                        const key = `${f.kind}:${f.id}`;
                        return (
                          <TableRow key={key}>
                            <TableCell>
                              <input
                                type="checkbox"
                                className="h-4 w-4 accent-primary"
                                checked={!!selected[key]}
                                onChange={(e) => setSelected((prev) => ({ ...prev, [key]: e.target.checked }))}
                              />
                            </TableCell>
                            <TableCell>
                              <span className={`inline-flex items-center rounded-full border px-2 py-1 text-xs ${sevTone(f.severity)}`}>
                                {f.severity.toUpperCase()}
                              </span>
                            </TableCell>
                            <TableCell>
                              <Badge variant="outline" className={`text-xs ${statusTone(f.status)}`}>
                                {f.status.toUpperCase()}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-sm">{f.asset_name}</TableCell>
                            <TableCell className="text-sm">
                              <div className="font-medium">{f.title}</div>
                              <div className="text-xs text-muted-foreground">
                                {f.kind.toUpperCase()} · SLA {f.sla_days}d {f.overdue ? "· OVERDUE" : ""}
                              </div>
                            </TableCell>
                            <TableCell className={`text-sm ${f.overdue ? "text-rose-700" : "text-muted-foreground"}`}>
                              {f.age_days}d
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">
                              {(f.owner_team || "—") + (f.owner_contact ? ` · ${f.owner_contact}` : "")}
                            </TableCell>
                          </TableRow>
                        );
                      })
                    )}
                    {!findingLoading && groupFindings.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={7} className="text-sm text-muted-foreground">
                          No findings for this group/status.
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </DialogContent>
          </Dialog>
        </>
      )}
    </div>
  );
}

