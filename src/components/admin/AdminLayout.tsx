import { useEffect, useState } from "react";
import { Outlet, Link, useLocation, useNavigate } from "react-router-dom";
import { Shield, Users, Building2, ClipboardList, AlertTriangle, Activity, Menu, X, LayoutDashboard, LogOut, Inbox, FileText, Cloud, Kanban } from "lucide-react";
import { PaginatedResponse, apiRequest, setAccessToken } from "@/lib/api";
import { ThemeToggle } from "@/components/theme/ThemeToggle";
import { ServiceRequest } from "@/lib/types";

const navItems = [
  { label: "Operations Overview", icon: LayoutDashboard, href: "/admin" },
  { label: "Organizations", icon: Building2, href: "/admin/organizations" },
  { label: "Users", icon: Users, href: "/admin/users" },
  { label: "Scan Jobs", icon: ClipboardList, href: "/admin/scan-jobs" },
  { label: "Service Requests", icon: Inbox, href: "/admin/service-requests" },
  { label: "Triage", icon: Kanban, href: "/admin/triage" },
  { label: "Reports", icon: FileText, href: "/admin/reports" },
  { label: "Cloud Accounts", icon: Cloud, href: "/admin/cloud-accounts" },
  { label: "Incidents", icon: AlertTriangle, href: "/admin/incidents" },
  { label: "Activity Log", icon: Activity, href: "/admin/activity-log" },
];

export default function AdminLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [authChecked, setAuthChecked] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [pendingCount, setPendingCount] = useState(0);

  useEffect(() => {
    apiRequest("/internal/organizations/")
      .then(() => setAuthChecked(true))
      .catch(() => {
        setAuthError("Access restricted. Please contact the platform owner.");
        navigate("/admin/login");
      });
  }, [navigate]);

  useEffect(() => {
    let mounted = true;

    const refreshPendingCount = async () => {
      try {
        const data = await apiRequest<PaginatedResponse<ServiceRequest>>("/internal/service-requests/?status=PENDING");
        if (!mounted) return;
        const count = typeof data.count === "number" ? data.count : data.results?.length || 0;
        setPendingCount(count);
      } catch {
        if (!mounted) return;
        setPendingCount(0);
      }
    };

    refreshPendingCount();
    const interval = window.setInterval(refreshPendingCount, 5000);
    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, []);

  const sidebarContent = (
    <>
      <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-1">
        {navItems.map((item) => {
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
              <span className="flex-1">{item.label}</span>
              {item.href === "/admin/service-requests" && pendingCount > 0 && (
                <span className="ml-auto rounded-full bg-primary/15 px-2 py-0.5 text-xs font-semibold text-primary">
                  {pendingCount}
                </span>
              )}
            </Link>
          );
        })}
      </nav>
      <div className="border-t border-border p-3">
        <button
          onClick={() => { setAccessToken(null); navigate("/admin/login"); setMobileOpen(false); }}
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
      <aside className="hidden h-screen w-60 flex-col border-r border-border bg-card md:flex">
        <div className="flex h-16 items-center gap-2 border-b border-border px-5">
          <Shield className="h-6 w-6 text-primary" />
          <span className="font-display text-lg font-bold">Aegis Admin</span>
        </div>
        <div className="flex flex-1 flex-col min-h-0">
          {sidebarContent}
        </div>
      </aside>

      {mobileOpen && (
        <div className="fixed inset-0 z-40 md:hidden" onClick={() => setMobileOpen(false)}>
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
        </div>
      )}

      <aside
        className={`fixed inset-y-0 left-0 z-50 w-64 flex flex-col bg-card border-r border-border transform transition-transform duration-200 ease-in-out md:hidden ${
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex h-16 items-center justify-between border-b border-border px-5">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <span className="font-display text-lg font-bold">Aegis Admin</span>
          </div>
          <button onClick={() => setMobileOpen(false)} className="text-muted-foreground hover:text-foreground">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="flex flex-1 flex-col min-h-0">
          {sidebarContent}
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto">
        <div className="flex h-16 items-center gap-3 border-b border-border px-4 md:hidden">
          <button onClick={() => setMobileOpen(true)} className="text-muted-foreground hover:text-foreground">
            <Menu className="h-6 w-6" />
          </button>
          <Shield className="h-6 w-6 text-primary" />
          <span className="font-display text-lg font-bold">Aegis Admin</span>
        </div>
        <div className="p-6 md:p-8">
          <div className="mb-6 flex items-center justify-between">
            <div>
              {!authChecked && !authError && <p className="text-sm text-muted-foreground">Checking access...</p>}
              {authError && <p className="text-sm text-destructive">{authError}</p>}
            </div>
            <ThemeToggle />
          </div>
          {authChecked && <Outlet />}
        </div>
      </main>
    </div>
  );
}
