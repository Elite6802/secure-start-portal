import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useOutletContext } from "react-router-dom";
import { Activity, AlertTriangle, BarChart3, Network, ShieldCheck } from "lucide-react";
import { Area, AreaChart, Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { apiRequest } from "@/lib/api";
import { AnalystMetrics } from "@/lib/types";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";

type ChartTooltipPayload = { dataKey?: string; name?: string; value?: number | string; color?: string };
type ChartTooltipProps = { active?: boolean; payload?: ChartTooltipPayload[]; label?: string | number };

const ChartTooltip = ({ active, payload, label }: ChartTooltipProps) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-border bg-card px-3 py-2 text-xs shadow-lg">
      <p className="font-medium text-foreground mb-1">{label}</p>
      {payload.map((item) => (
        <p key={item.dataKey ?? item.name} className="flex justify-between gap-4" style={{ color: item.color }}>
          <span className="text-muted-foreground">{item.name ?? item.dataKey}</span>
          <span className="font-semibold">{item.value}</span>
        </p>
      ))}
    </div>
  );
};

export default function AnalystDashboard() {
  const { accessRole } = useOutletContext<{ accessRole?: string | null }>();
  const canAccess = accessRole === "Security Lead";
  const navigate = useNavigate();
  const [metrics, setMetrics] = useState<AnalystMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeDetail, setActiveDetail] = useState<null | "open_findings" | "assets_at_risk" | "active_scans" | "mttr">(null);

  useEffect(() => {
    if (!canAccess) return;
    const load = async () => {
      try {
        setLoading(true);
        setError(null);
        const data = await apiRequest<AnalystMetrics>("/scan-metrics/");
        setMetrics(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load analyst metrics.");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [canAccess]);

  const scanVolume = useMemo(() => {
    if (!metrics) return [];
    return metrics.scan_volume.map((item) => ({
      date: item.period.slice(5),
      code: item.code,
      web: item.web,
      network: item.network,
      infra: item.infrastructure,
    }));
  }, [metrics]);

  const severitySummary = useMemo(() => {
    if (!metrics) return { critical: 0, high: 0, moderate: 0, low: 0 };
    return {
      critical: metrics.summary.critical,
      high: metrics.summary.high,
      moderate: metrics.summary.moderate,
      low: metrics.summary.low,
    };
  }, [metrics]);

  const severityChart = useMemo(() => [
    { name: "Critical", value: severitySummary.critical, fill: "hsl(var(--destructive))" },
    { name: "High", value: severitySummary.high, fill: "hsl(var(--warning))" },
    { name: "Moderate", value: severitySummary.moderate, fill: "hsl(var(--primary))" },
    { name: "Low", value: severitySummary.low, fill: "hsl(var(--muted-foreground))" },
  ], [severitySummary]);

  const findingTypeChart = useMemo(() => {
    if (!metrics) return [];
    const palette = [
      "hsl(var(--destructive))",
      "hsl(var(--warning))",
      "hsl(var(--primary))",
      "hsl(var(--accent))",
      "hsl(var(--secondary-foreground))",
      "hsl(var(--muted-foreground))",
      "hsl(var(--success))",
    ];
    return metrics.finding_breakdown
      .filter((item) => item.value > 0)
      .map((item, idx) => ({ ...item, fill: palette[idx % palette.length] }));
  }, [metrics]);

  const exposureHotspots = useMemo(() => {
    if (!metrics) return [];
    return metrics.exposure_hotspots;
  }, [metrics]);

  const reportTrend = useMemo(() => {
    if (!metrics) return [];
    return metrics.report_trend.map((item) => ({ date: item.period.slice(5), count: item.count }));
  }, [metrics]);

  const openFindings = metrics?.summary.open_findings ?? 0;
  const totalScans = metrics?.summary.active_scans ?? 0;
  const reportsReady = metrics?.summary.reports_ready ?? 0;
  const assetsAtRisk = metrics?.summary.assets_at_risk ?? 0;
  const mttrDays = metrics?.summary.mttr_days;

  if (!canAccess) {
    return (
      <div className="rounded-2xl border border-border bg-card p-10 text-center">
        <h1 className="font-display text-2xl font-bold mb-2">Analyst Workspace</h1>
        <p className="text-sm text-muted-foreground">This workspace is available to Security Lead roles only.</p>
      </div>
    );
  }

  if (loading) {
    return <div className="text-sm text-muted-foreground">Loading analyst dashboard...</div>;
  }

  if (error) {
    return (
      <div className="rounded-xl border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
        {error}
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="font-display text-2xl font-bold mb-2">Analyst Workspace</h1>
        <p className="text-sm text-muted-foreground">
          Unified analyst view across scan execution, exposure trends, and remediation priorities.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[
          { label: "Open Findings", value: openFindings, icon: AlertTriangle, tone: "text-destructive", key: "open_findings" as const },
          { label: "Assets At Risk", value: assetsAtRisk, icon: Network, tone: "text-warning", key: "assets_at_risk" as const },
          { label: "Active Scans", value: totalScans, icon: Activity, tone: "text-primary", key: "active_scans" as const },
          { label: "MTTR (days)", value: mttrDays ?? "—", icon: ShieldCheck, tone: "text-success", key: "mttr" as const },
        ].map((card) => (
          <button
            key={card.label}
            type="button"
            onClick={() => setActiveDetail(card.key)}
            className="rounded-2xl border border-border bg-card/60 p-4 text-left shadow-sm transition hover:border-primary/30 hover:bg-card/75 focus:outline-none focus:ring-2 focus:ring-primary/30"
          >
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted-foreground">{card.label}</p>
              <card.icon className={`h-4 w-4 ${card.tone}`} />
            </div>
            <p className="mt-2 text-2xl font-semibold">{card.value}</p>
            <p className="mt-2 text-[11px] text-muted-foreground">View details</p>
          </button>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="rounded-2xl border border-border bg-card/60 p-5 lg:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-foreground">Scan Throughput</h2>
              <p className="text-xs text-muted-foreground">Recent scan volume across domains</p>
            </div>
            <ShieldCheck className="h-4 w-4 text-primary" />
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={scanVolume} margin={{ left: -20, right: 10 }}>
                <XAxis dataKey="date" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                <Tooltip content={<ChartTooltip />} />
                <Area type="monotone" dataKey="code" stroke="hsl(var(--primary))" fill="hsl(var(--primary)/0.2)" />
                <Area type="monotone" dataKey="web" stroke="hsl(var(--accent))" fill="hsl(var(--accent)/0.2)" />
                <Area type="monotone" dataKey="network" stroke="hsl(var(--warning))" fill="hsl(var(--warning)/0.2)" />
              <Area type="monotone" dataKey="infra" stroke="hsl(var(--destructive))" fill="hsl(var(--destructive)/0.18)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

        <div className="rounded-2xl border border-border bg-card/60 p-5">
          <div className="mb-4">
            <h2 className="text-sm font-semibold text-foreground">Finding Severity</h2>
            <p className="text-xs text-muted-foreground">Combined code + network exposure</p>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={severityChart} dataKey="value" innerRadius={45} outerRadius={80} paddingAngle={3}>
                  {severityChart.map((entry) => (
                    <Cell key={entry.name} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip content={<ChartTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="rounded-2xl border border-border bg-card/60 p-5">
          <div className="mb-4">
            <h2 className="text-sm font-semibold text-foreground">Exposure Mix</h2>
            <p className="text-xs text-muted-foreground">Code + network finding categories</p>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={findingTypeChart} layout="vertical" margin={{ left: 20 }}>
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" width={110} tick={{ fontSize: 10 }} />
                <Tooltip content={<ChartTooltip />} />
                <Bar dataKey="value" radius={[6, 6, 6, 6]}>
                  {findingTypeChart.map((entry) => (
                    <Cell key={entry.name} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-2xl border border-border bg-card/60 p-5 lg:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-foreground">Report Velocity</h2>
              <p className="text-xs text-muted-foreground">Reports generated over time · {reportsReady} available</p>
            </div>
            <BarChart3 className="h-4 w-4 text-primary" />
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
                <BarChart data={reportTrend} margin={{ left: -20, right: 10 }}>
                  <XAxis dataKey="date" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                  <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                  <Tooltip content={<ChartTooltip />} />
                  <Bar dataKey="count" fill="hsl(var(--primary))" radius={[6, 6, 0, 0]} />
                </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="rounded-2xl border border-border bg-card/60 p-5">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-foreground">Exposure Hotspots</h2>
            <p className="text-xs text-muted-foreground">Top hosts/ports with repeated findings</p>
          </div>
          <Network className="h-4 w-4 text-warning" />
        </div>
        {exposureHotspots.length === 0 ? (
          <p className="text-sm text-muted-foreground">No network findings recorded yet.</p>
        ) : (
           <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
             {exposureHotspots.map((item) => (
              <button
                key={item.label}
                type="button"
                onClick={() => navigate(`/dashboard/network-security?endpoint=${encodeURIComponent(item.label)}`)}
                className="rounded-xl border border-border bg-background/60 p-3 text-left transition hover:border-primary/40 hover:bg-background/75 focus:outline-none focus:ring-2 focus:ring-primary/30"
              >
                <p className="text-xs text-muted-foreground">Endpoint</p>
                <p className="text-sm font-semibold text-foreground">{item.label}</p>
                <p className="mt-1 text-xs text-muted-foreground">Findings</p>
                <p className="text-lg font-semibold">{item.count}</p>
                <p className="mt-2 text-[11px] text-muted-foreground">View details</p>
              </button>
             ))}
           </div>
         )}
       </div>

       <Dialog open={activeDetail !== null} onOpenChange={(open) => (!open ? setActiveDetail(null) : null)}>
         <DialogContent className="max-w-3xl">
           <DialogHeader>
             <DialogTitle>
               {activeDetail === "open_findings" && "Open Findings"}
               {activeDetail === "assets_at_risk" && "Assets At Risk"}
               {activeDetail === "active_scans" && "Active Scans"}
               {activeDetail === "mttr" && "MTTR (Mean Time To Remediate)"}
             </DialogTitle>
             <DialogDescription>
               {activeDetail === "open_findings" && "Severity + category mix and a sample of recent items."}
               {activeDetail === "assets_at_risk" && "Assets currently flagged with elevated risk."}
               {activeDetail === "active_scans" && "Current queue/running scan jobs (if any) and links to details."}
               {activeDetail === "mttr" && "Resolution time overview from recorded incident data."}
             </DialogDescription>
           </DialogHeader>

           <ScrollArea className="max-h-[70vh] pr-4">
             {activeDetail === "open_findings" && metrics && (
               <div className="space-y-4">
                 <div className="rounded-xl border border-border bg-background/60 p-4">
                   <p className="text-sm font-semibold mb-1">How This Is Calculated</p>
                   <p className="text-sm text-muted-foreground">
                     “Open Findings” is the current aggregated count of unresolved findings across scan domains in the analyst summary.
                     Use the links below to review the underlying findings and remediation guidance.
                   </p>
                 </div>

                 <div className="grid gap-3 sm:grid-cols-4">
                   {[
                     { label: "Critical", value: metrics.summary.critical },
                     { label: "High", value: metrics.summary.high },
                     { label: "Moderate", value: metrics.summary.moderate },
                     { label: "Low", value: metrics.summary.low },
                   ].map((row) => (
                     <div key={row.label} className="rounded-xl border border-border bg-background/60 p-3">
                       <p className="text-xs text-muted-foreground">{row.label}</p>
                       <p className="mt-1 text-xl font-semibold">{row.value}</p>
                     </div>
                   ))}
                 </div>

                 <div className="rounded-xl border border-border bg-background/60 p-4">
                   <p className="text-sm font-semibold mb-2">Where To Review</p>
                   <div className="flex flex-wrap gap-2">
                     <Button variant="outline" size="sm" asChild>
                       <Link to="/dashboard/code-security">Code Findings</Link>
                     </Button>
                     <Button variant="outline" size="sm" asChild>
                       <Link to="/dashboard/network-security">Network Findings</Link>
                     </Button>
                     <Button variant="outline" size="sm" asChild>
                       <Link to="/dashboard/reports">Reports</Link>
                     </Button>
                   </div>
                 </div>
               </div>
             )}

             {activeDetail === "assets_at_risk" && (
               <div className="space-y-4">
                 <div className="rounded-xl border border-border bg-background/60 p-4">
                   <p className="text-sm font-semibold mb-1">How This Is Calculated</p>
                   <p className="text-sm text-muted-foreground">
                     “Assets At Risk” is an aggregated count of assets currently flagged for elevated exposure or risk based on recent scan results.
                     Review the asset inventory to see which assets are impacted.
                   </p>
                 </div>
                 <div className="rounded-xl border border-border bg-background/60 p-4">
                   <p className="text-sm font-semibold mb-2">Where To Review</p>
                   <Button variant="outline" size="sm" asChild>
                     <Link to="/dashboard/assets">Open Inventory</Link>
                   </Button>
                 </div>
               </div>
             )}

             {activeDetail === "active_scans" && (
               <div className="space-y-4">
                 <div className="rounded-xl border border-border bg-background/60 p-4">
                   <p className="text-sm font-semibold mb-1">How This Is Calculated</p>
                   <p className="text-sm text-muted-foreground">
                     “Active Scans” is the current number of scan jobs in progress (queued/running) in the analyst summary.
                     Use the scans page for job-level status, failures, and output.
                   </p>
                 </div>
                 <div className="rounded-xl border border-border bg-background/60 p-4">
                   <p className="text-sm font-semibold mb-2">Where To Review</p>
                   <Button variant="outline" size="sm" asChild>
                     <Link to="/dashboard/scans">Open Scans</Link>
                   </Button>
                 </div>
               </div>
             )}

             {activeDetail === "mttr" && (
               <div className="space-y-4">
                 <div className="rounded-xl border border-border bg-background/60 p-4">
                   <p className="text-sm font-semibold mb-1">How This Is Calculated</p>
                   <p className="text-sm text-muted-foreground">
                     “MTTR (days)” is derived from incident records with resolution timestamps. It represents the average time to remediate issues once tracked as incidents.
                     If no resolved incidents exist yet, the value will be unavailable.
                   </p>
                 </div>
                 <div className="rounded-xl border border-border bg-background/60 p-4">
                   <p className="text-sm font-semibold mb-2">Where To Review</p>
                   <Button variant="outline" size="sm" asChild>
                     <Link to="/dashboard/incidents">Open Incidents</Link>
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
