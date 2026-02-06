import { Outlet, Link, useLocation, useNavigate } from "react-router-dom";
import { Shield, LayoutDashboard, Server, Scan, Code2, FileText, AlertTriangle, Settings, LogOut } from "lucide-react";

const navItems = [
  { label: "Dashboard", icon: LayoutDashboard, href: "/dashboard" },
  { label: "Assets", icon: Server, href: "/dashboard/assets" },
  { label: "Scans", icon: Scan, href: "/dashboard/scans" },
  { label: "Code Security", icon: Code2, href: "/dashboard/code-security" },
  { label: "Reports", icon: FileText, href: "/dashboard/reports" },
  { label: "Incidents", icon: AlertTriangle, href: "/dashboard/incidents" },
  { label: "Settings", icon: Settings, href: "/dashboard/settings" },
];

export default function DashboardLayout() {
  const location = useLocation();
  const navigate = useNavigate();

  return (
    <div className="dark flex min-h-screen bg-background text-foreground">
      {/* Sidebar */}
      <aside className="hidden w-60 flex-col border-r border-border bg-card md:flex">
        <div className="flex h-16 items-center gap-2 border-b border-border px-5">
          <Shield className="h-6 w-6 text-primary" />
          <span className="font-display text-lg font-bold">Aegis</span>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1">
          {navItems.map((item) => {
            const active = location.pathname === item.href;
            return (
              <Link
                key={item.href}
                to={item.href}
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
            onClick={() => navigate("/login")}
            className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium text-muted-foreground hover:bg-secondary hover:text-foreground transition-colors"
          >
            <LogOut className="h-4 w-4" />
            Logout
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        {/* Mobile header */}
        <div className="flex h-16 items-center gap-3 border-b border-border px-4 md:hidden">
          <Shield className="h-6 w-6 text-primary" />
          <span className="font-display text-lg font-bold">Aegis</span>
        </div>
        <div className="p-6 md:p-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
