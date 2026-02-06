import { Shield, Activity, FileText, AlertTriangle, Server, Scan } from "lucide-react";
import { dashboardStats } from "@/data/mockData";

const stats = [
  { label: "Security Score", value: `${dashboardStats.securityScore}/100`, icon: Shield, color: "text-primary" },
  { label: "Assets Monitored", value: dashboardStats.assetsMonitored, icon: Server, color: "text-accent" },
  { label: "Scans This Month", value: dashboardStats.scansThisMonth, icon: Scan, color: "text-primary" },
  { label: "Active Incidents", value: dashboardStats.activeIncidents, icon: AlertTriangle, color: "text-warning" },
  { label: "Last Report", value: dashboardStats.lastReportDate, icon: FileText, color: "text-muted-foreground" },
  { label: "Last Scan", value: dashboardStats.lastScanDate, icon: Activity, color: "text-success" },
];

export default function DashboardHome() {
  const { riskSummary } = dashboardStats;

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Security Overview</h1>
      <p className="text-sm text-muted-foreground mb-8">Your organization's security posture at a glance.</p>

      {/* Stat Cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {stats.map((s) => (
          <div key={s.label} className="glass-card rounded-xl p-5">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-medium text-muted-foreground">{s.label}</span>
              <s.icon className={`h-4 w-4 ${s.color}`} />
            </div>
            <p className="font-display text-2xl font-bold">{s.value}</p>
          </div>
        ))}
      </div>

      {/* Risk Summary */}
      <div className="mt-8 glass-card rounded-xl p-6">
        <h2 className="font-display text-lg font-semibold mb-4">Risk Summary</h2>
        <div className="grid grid-cols-3 gap-4">
          <div className="rounded-lg bg-destructive/10 p-4 text-center">
            <p className="text-3xl font-bold text-destructive font-display">{riskSummary.high}</p>
            <p className="text-xs text-muted-foreground mt-1">High</p>
          </div>
          <div className="rounded-lg bg-warning/10 p-4 text-center">
            <p className="text-3xl font-bold text-warning font-display">{riskSummary.medium}</p>
            <p className="text-xs text-muted-foreground mt-1">Medium</p>
          </div>
          <div className="rounded-lg bg-primary/10 p-4 text-center">
            <p className="text-3xl font-bold text-primary font-display">{riskSummary.low}</p>
            <p className="text-xs text-muted-foreground mt-1">Low</p>
          </div>
        </div>
      </div>
    </div>
  );
}
