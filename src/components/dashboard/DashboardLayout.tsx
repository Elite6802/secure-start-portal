import { useMemo, useRef, useState } from "react";
import { Outlet, Link, useLocation, useNavigate } from "react-router-dom";
import { Shield, LayoutDashboard, Server, Scan, Code2, FileText, AlertTriangle, Settings, LogOut, Menu, X, Network, ClipboardCheck, Activity, BarChart3 } from "lucide-react";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { useEffect } from "react";
import { PaginatedResponse, apiRequest, getMe, setAccessToken, unwrapResults } from "@/lib/api";
import { ThemeToggle } from "@/components/theme/ThemeToggle";
import { toast } from "@/components/ui/use-toast";
import { Report, UserAccount } from "@/lib/types";

const navItems = [
  { label: "Security Posture Overview", icon: LayoutDashboard, href: "/dashboard", roles: ["Security Lead", "Developer", "Executive"] },
  { label: "Protected Assets Inventory", icon: Server, href: "/dashboard/assets", roles: ["Security Lead"] },
  { label: "Automated Security Scans", icon: Scan, href: "/dashboard/scans", roles: ["Security Lead"] },
  { label: "Network Security", icon: Network, href: "/dashboard/network-security", roles: ["Security Lead"] },
  { label: "Code Repository Security", icon: Code2, href: "/dashboard/code-security", roles: ["Security Lead", "Developer"] },
  { label: "Compliance Mapping", icon: ClipboardCheck, href: "/dashboard/compliance", roles: ["Security Lead", "Executive"] },
  { label: "Security Reports", icon: FileText, href: "/dashboard/reports", roles: ["Security Lead", "Executive"] },
  { label: "Analyst Workspace", icon: BarChart3, href: "/dashboard/analyst", roles: ["Security Lead"] },
  { label: "Security Incidents", icon: AlertTriangle, href: "/dashboard/incidents", roles: ["Security Lead", "Executive"] },
  { label: "Activity and Audit Log", icon: Activity, href: "/dashboard/activity", roles: ["Security Lead"] },
  { label: "Account Settings", icon: Settings, href: "/dashboard/settings", roles: ["Security Lead", "Developer", "Executive"] },
];

const roleOptions = ["Security Lead", "Developer", "Executive"] as const;
type RoleOption = (typeof roleOptions)[number];

const roleMap: Record<string, RoleOption> = {
  security_lead: "Security Lead",
  developer: "Developer",
  executive: "Executive",
  soc_admin: "Security Lead",
};

export default function DashboardLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [role, setRole] = useState<RoleOption>("Security Lead");
  const [accessRole, setAccessRole] = useState<RoleOption | null>(null);
  const [hasSelectedRole, setHasSelectedRole] = useState(false);
  const [orgName, setOrgName] = useState<string | null>(null);
  const [orgDomain, setOrgDomain] = useState<string | null>(null);
  const reportIdsRef = useRef<Set<string>>(new Set());
  const reportReadyRef = useRef(false);
  const [reportNoticeCount, setReportNoticeCount] = useState(0);
  const [latestReportId, setLatestReportId] = useState<string | null>(null);

  const reportSeenKey = useMemo(() => "aegis_seen_reports", []);

  useEffect(() => {
    let mounted = true;
    getMe()
      .then((me) => {
        const account = me as UserAccount | null;
        const memberships = Array.isArray(account?.memberships)
          ? (account.memberships as Array<{
              role?: string;
              is_primary?: boolean;
              organization?: { name?: string; domain?: string };
            }>)
          : [];
        const primary = memberships.find((m) => m.is_primary) ?? memberships[0];
        const mappedRole = roleMap[primary?.role ?? ""] ?? "Executive";
        if (!mounted) return;
        setAccessRole(mappedRole);
        if (!hasSelectedRole) {
          setRole(mappedRole);
        }
        setOrgName(primary?.organization?.name || null);
        setOrgDomain(primary?.organization?.domain || null);
      })
      .catch(() => {
        navigate("/login");
      });
    return () => {
      mounted = false;
    };
  }, [navigate, hasSelectedRole]);

  useEffect(() => {
    if (!accessRole || !["Security Lead", "Executive"].includes(accessRole)) {
      return;
    }
    let mounted = true;

    const fetchReports = async (notify: boolean) => {
      try {
        const data = await apiRequest<PaginatedResponse<Report>>("/reports/");
        if (!mounted) return;
        const reports = unwrapResults<Report>(data);
        const nextIds = new Set(reports.map((report) => report.id));
        const seen = new Set<string>(JSON.parse(localStorage.getItem(reportSeenKey) || "[]"));
        const unseen = reports.filter((report) => !seen.has(report.id));
        setReportNoticeCount(unseen.length);
        setLatestReportId(unseen[0]?.id || null);
        if (reportReadyRef.current && notify && unseen.length > 0) {
          toast({
            title: "Report ready",
            description: "A new security report is available.",
          });
        }
        reportIdsRef.current = nextIds;
        reportReadyRef.current = true;
      } catch {
        if (!mounted) return;
      }
    };

    fetchReports(false);
    const interval = window.setInterval(() => {
      fetchReports(true);
    }, 15000);
    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, [accessRole, reportSeenKey]);

  const handleReportNoticeClick = () => {
    const allIds = Array.from(reportIdsRef.current);
    localStorage.setItem(reportSeenKey, JSON.stringify(allIds));
    setReportNoticeCount(0);
    navigate("/dashboard/reports", {
      state: { highlightReportId: latestReportId },
    });
  };

  const sidebarContent = (
    <>
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
        {navItems.filter((item) => item.roles.includes(role)).map((item) => {
          const active = location.pathname === item.href;
          return (
            <Link
              key={item.href}
              to={item.href}
              onClick={() => setMobileOpen(false)}
              className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors ${
                active
                  ? "bg-primary/10 text-primary"
                  : "text-muted-foreground hover:bg-secondary hover:text-foreground"
              }`}
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>
      <div className="border-t border-border p-3">
        <button
          onClick={() => { setAccessToken(null); navigate("/login"); setMobileOpen(false); }}
          className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-muted-foreground hover:bg-secondary hover:text-foreground transition-colors"
        >
          <LogOut className="h-4 w-4" />
          Logout
        </button>
      </div>
    </>
  );

  return (
    <div className="flex h-screen bg-background text-foreground overflow-hidden">
      {/* Desktop Sidebar */}
      <aside className="hidden h-screen w-60 flex-col border-r border-border bg-card md:flex">
        <div className="flex h-16 items-center gap-2 border-b border-border px-5">
          <Shield className="h-6 w-6 text-primary" />
          <span className="font-display text-lg font-bold">Aegis</span>
        </div>
        <div className="flex flex-1 flex-col min-h-0">
          {sidebarContent}
        </div>
      </aside>

      {/* Mobile Overlay */}
      {mobileOpen && (
        <div className="fixed inset-0 z-40 md:hidden" onClick={() => setMobileOpen(false)}>
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
        </div>
      )}

      {/* Mobile Sidebar Drawer */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-64 flex flex-col bg-card border-r border-border transform transition-transform duration-200 ease-in-out md:hidden ${
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex h-16 items-center justify-between border-b border-border px-5">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <span className="font-display text-lg font-bold">Aegis</span>
          </div>
          <button onClick={() => setMobileOpen(false)} className="text-muted-foreground hover:text-foreground">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="flex flex-1 flex-col min-h-0">
          {sidebarContent}
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto">
        {/* Mobile header */}
        <div className="flex h-16 items-center gap-3 border-b border-border px-4 md:hidden">
          <button onClick={() => setMobileOpen(true)} className="text-muted-foreground hover:text-foreground">
            <Menu className="h-6 w-6" />
          </button>
          <Shield className="h-6 w-6 text-primary" />
          <span className="font-display text-lg font-bold">Aegis</span>
        </div>
        <div className="p-6 md:p-8">
          <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="text-xs text-muted-foreground space-y-1">
              <p>
                Viewing dashboard as <span className="font-semibold text-foreground">{role}</span>.
              </p>
              <p>
                Organization:{" "}
                <span className="font-semibold text-foreground">
                  {orgName || "Unassigned"}
                </span>
                {orgDomain ? <span className="text-muted-foreground"> · {orgDomain}</span> : null}
              </p>
            </div>
            <div className="flex w-full flex-col gap-3 sm:w-auto sm:flex-row sm:items-end">
              {reportNoticeCount > 0 && (
                <button
                  onClick={handleReportNoticeClick}
                  className="flex items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-3 py-1.5 text-xs font-semibold text-primary shadow-[0_0_16px_rgba(59,130,246,0.28)] hover:bg-primary/15"
                >
                  Report ready
                  <span className="rounded-full bg-primary text-primary-foreground px-2 py-0.5 text-[10px] font-semibold">
                    {reportNoticeCount}
                  </span>
                </button>
              )}
              <ThemeToggle />
              <div className="w-full sm:w-64">
              <Label className="text-xs text-muted-foreground">Role View</Label>
              <Select
                value={role}
                onValueChange={(value) => {
                  setRole(value as RoleOption);
                  setHasSelectedRole(true);
                }}
              >
                <SelectTrigger className="mt-1.5 bg-secondary">
                  <SelectValue placeholder="Select role" />
                </SelectTrigger>
                <SelectContent>
                  {roleOptions.map((option) => (
                    <SelectItem key={option} value={option}>
                      {option}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            </div>
          </div>
          <Outlet context={{ role, accessRole }} />
        </div>
      </main>
    </div>
  );
}
