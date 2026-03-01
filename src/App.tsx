import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "@/components/theme/ThemeProvider";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Routes, Route } from "react-router-dom";
import ScrollToTop from "./components/ScrollToTop";
import IdleLogoutGuard from "./components/auth/IdleLogoutGuard";
import Index from "./pages/Index";
import Pricing from "./pages/Pricing";
import Contact from "./pages/Contact";
import Login from "./pages/Login";
import DashboardLayout from "./components/dashboard/DashboardLayout";
import DashboardHome from "./pages/dashboard/DashboardHome";
import Assets from "./pages/dashboard/Assets";
import Scans from "./pages/dashboard/Scans";
import ScanDetails from "./pages/dashboard/ScanDetails";
import CodeSecurity from "./pages/dashboard/CodeSecurity";
import Reports from "./pages/dashboard/Reports";
import Incidents from "./pages/dashboard/Incidents";
import SettingsPage from "./pages/dashboard/Settings";
import NetworkSecurity from "./pages/dashboard/NetworkSecurity";
import ComplianceMapping from "./pages/dashboard/ComplianceMapping";
import ActivityLog from "./pages/dashboard/ActivityLog";
import AnalystDashboard from "./pages/dashboard/Analyst";
import AdminLayout from "./components/admin/AdminLayout";
import AdminHome from "./pages/admin/AdminHome";
import OrganizationsAdmin from "./pages/admin/Organizations";
import OrganizationDetailAdmin from "./pages/admin/OrganizationDetail";
import UsersAdmin from "./pages/admin/Users";
import ScanJobsAdmin from "./pages/admin/ScanJobs";
import ServiceRequestsAdmin from "./pages/admin/ScanRequests";
import ReportsAdmin from "./pages/admin/Reports";
import IncidentsAdmin from "./pages/admin/Incidents";
import ActivityLogAdmin from "./pages/admin/ActivityLog";
import CloudAccountsAdmin from "./pages/admin/CloudAccounts";
import AdminTriage from "./pages/admin/Triage";
import AdminLogin from "./pages/admin/AdminLogin";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <ThemeProvider>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <ScrollToTop />
        <IdleLogoutGuard />
        <Routes>
          <Route path="/" element={<Index />} />
          <Route path="/pricing" element={<Pricing />} />
          <Route path="/contact" element={<Contact />} />
          <Route path="/login" element={<Login />} />
          <Route path="/admin/login" element={<AdminLogin />} />
          <Route path="/dashboard" element={<DashboardLayout />}>
            <Route index element={<DashboardHome />} />
            <Route path="assets" element={<Assets />} />
            <Route path="scans" element={<Scans />} />
            <Route path="scans/:id" element={<ScanDetails />} />
            <Route path="network-security" element={<NetworkSecurity />} />
            <Route path="code-security" element={<CodeSecurity />} />
            <Route path="compliance" element={<ComplianceMapping />} />
            <Route path="reports" element={<Reports />} />
            <Route path="analyst" element={<AnalystDashboard />} />
            <Route path="incidents" element={<Incidents />} />
            <Route path="activity" element={<ActivityLog />} />
            <Route path="settings" element={<SettingsPage />} />
          </Route>
          <Route path="/admin" element={<AdminLayout />}>
            <Route index element={<AdminHome />} />
            <Route path="organizations" element={<OrganizationsAdmin />} />
            <Route path="organizations/:id" element={<OrganizationDetailAdmin />} />
            <Route path="users" element={<UsersAdmin />} />
            <Route path="scan-jobs" element={<ScanJobsAdmin />} />
            <Route path="service-requests" element={<ServiceRequestsAdmin />} />
            <Route path="triage" element={<AdminTriage />} />
            <Route path="reports" element={<ReportsAdmin />} />
            <Route path="cloud-accounts" element={<CloudAccountsAdmin />} />
            <Route path="incidents" element={<IncidentsAdmin />} />
            <Route path="activity-log" element={<ActivityLogAdmin />} />
          </Route>
          <Route path="*" element={<NotFound />} />
        </Routes>
      </TooltipProvider>
    </ThemeProvider>
  </QueryClientProvider>
);

export default App;
