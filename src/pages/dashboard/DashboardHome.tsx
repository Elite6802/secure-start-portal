import { Shield, Activity, FileText, AlertTriangle, Server, Scan } from "lucide-react";
import { Area, AreaChart, Bar, BarChart, Cell, Pie, PieChart, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { dashboardStats, securityScoreTrend, severityDistribution, scanHistory } from "@/data/mockData";

const stats = [
  { label: "Security Score", value: `${dashboardStats.securityScore}/100`, icon: Shield, color: "text-primary" },
  { label: "Assets Monitored", value: dashboardStats.assetsMonitored, icon: Server, color: "text-accent" },
  { label: "Scans This Month", value: dashboardStats.scansThisMonth, icon: Scan, color: "text-primary" },
  { label: "Active Incidents", value: dashboardStats.activeIncidents, icon: AlertTriangle, color: "text-warning" },
  { label: "Last Report", value: dashboardStats.lastReportDate, icon: FileText, color: "text-muted-foreground" },
  { label: "Last Scan", value: dashboardStats.lastScanDate, icon: Activity, color: "text-success" },
];

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-border bg-card px-3 py-2 text-xs shadow-lg">
      <p className="font-medium text-foreground mb-1">{label}</p>
      {payload.map((p: any) => (
        <p key={p.dataKey} style={{ color: p.color }} className="flex justify-between gap-4">
          <span className="text-muted-foreground">{p.name ?? p.dataKey}</span>
          <span className="font-semibold">{p.value}</span>
        </p>
      ))}
    </div>
  );
};

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

      {/* Charts Row */}
      <div className="mt-8 grid gap-6 lg:grid-cols-2">
        {/* Security Score Trend */}
        <div className="glass-card rounded-xl p-6">
          <h2 className="font-display text-lg font-semibold mb-4">Security Score Trend</h2>
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={securityScoreTrend}>
              <defs>
                <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
              <XAxis dataKey="month" tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} axisLine={false} tickLine={false} />
              <YAxis domain={[50, 100]} tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="score" stroke="hsl(var(--primary))" strokeWidth={2} fill="url(#scoreGradient)" name="Score" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Distribution */}
        <div className="glass-card rounded-xl p-6">
          <h2 className="font-display text-lg font-semibold mb-4">Severity Distribution</h2>
          <ResponsiveContainer width="100%" height={240}>
            <PieChart>
              <Pie data={severityDistribution} cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={4} dataKey="value" nameKey="name" stroke="none">
                {severityDistribution.map((entry) => (
                  <Cell key={entry.name} fill={entry.fill} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
              <Legend
                formatter={(value: string) => <span className="text-xs text-muted-foreground">{value}</span>}
                iconType="circle"
                iconSize={8}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Scan History */}
      <div className="mt-6 glass-card rounded-xl p-6">
        <h2 className="font-display text-lg font-semibold mb-4">Scan History</h2>
        <ResponsiveContainer width="100%" height={240}>
          <BarChart data={scanHistory} barGap={2}>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
            <XAxis dataKey="date" tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 12 }} axisLine={false} tickLine={false} />
            <Tooltip content={<CustomTooltip />} />
            <Legend
              formatter={(value: string) => <span className="text-xs text-muted-foreground">{value}</span>}
              iconType="circle"
              iconSize={8}
            />
            <Bar dataKey="infra" name="Infrastructure" fill="hsl(var(--primary))" radius={[3, 3, 0, 0]} />
            <Bar dataKey="web" name="Web & API" fill="hsl(var(--accent))" radius={[3, 3, 0, 0]} />
            <Bar dataKey="code" name="Code" fill="hsl(var(--warning))" radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Risk Summary */}
      <div className="mt-6 glass-card rounded-xl p-6">
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
