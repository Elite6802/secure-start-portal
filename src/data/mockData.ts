export const assets = [
  { id: "AST-001", name: "api.clientapp.io", type: "Web Application", status: "Monitored", lastScan: "2026-02-04", risk: "Low" },
  { id: "AST-002", name: "192.168.1.0/24", type: "IP / Network", status: "Monitored", lastScan: "2026-02-03", risk: "Medium" },
  { id: "AST-003", name: "app.clientapp.io", type: "Domain", status: "Monitored", lastScan: "2026-02-05", risk: "Low" },
  { id: "AST-004", name: "aws-prod-cluster", type: "Cloud Resource", status: "Monitored", lastScan: "2026-02-01", risk: "High" },
  { id: "AST-005", name: "github.com/client/backend", type: "Code Repository", status: "Monitored", lastScan: "2026-02-05", risk: "Medium" },
  { id: "AST-006", name: "github.com/client/frontend", type: "Code Repository", status: "Monitored", lastScan: "2026-02-04", risk: "Low" },
];

export const scans = [
  { id: "SCN-001", type: "Infrastructure Scan", target: "192.168.1.0/24", status: "Completed", severity: { high: 1, medium: 3, low: 5 }, startedAt: "2026-02-03 09:00", completedAt: "2026-02-03 09:45" },
  { id: "SCN-002", type: "Web & API Scan", target: "api.clientapp.io", status: "Completed", severity: { high: 0, medium: 2, low: 8 }, startedAt: "2026-02-04 14:00", completedAt: "2026-02-04 14:30" },
  { id: "SCN-003", type: "Code Security (SAST)", target: "github.com/client/backend", status: "Completed", severity: { high: 2, medium: 5, low: 12 }, startedAt: "2026-02-05 08:00", completedAt: "2026-02-05 08:20" },
  { id: "SCN-004", type: "Dependency Scan", target: "github.com/client/frontend", status: "In Progress", severity: { high: 0, medium: 0, low: 0 }, startedAt: "2026-02-06 10:00", completedAt: null },
  { id: "SCN-005", type: "Container Scan", target: "aws-prod-cluster", status: "Scheduled", severity: { high: 0, medium: 0, low: 0 }, startedAt: null, completedAt: null },
];

export const codeRepos = [
  {
    id: "REPO-001",
    name: "client/backend",
    language: "Python",
    lastScan: "2026-02-05",
    scanTypes: ["Static Analysis", "Secrets Detection", "Dependency Check", "Secure Coding Standards"],
    findings: { critical: 0, high: 2, medium: 5, low: 12 },
    standards: ["OWASP Top 10", "CWE/SANS Top 25", "PCI DSS"],
  },
  {
    id: "REPO-002",
    name: "client/frontend",
    language: "TypeScript",
    lastScan: "2026-02-04",
    scanTypes: ["Static Analysis", "Dependency Check", "Secure Coding Standards"],
    findings: { critical: 0, high: 0, medium: 3, low: 7 },
    standards: ["OWASP Top 10", "Secure Coding Guidelines"],
  },
  {
    id: "REPO-003",
    name: "client/mobile-app",
    language: "Kotlin",
    lastScan: "2026-02-02",
    scanTypes: ["Static Analysis", "Secrets Detection", "Dependency Check"],
    findings: { critical: 1, high: 1, medium: 4, low: 9 },
    standards: ["OWASP Mobile Top 10", "CWE/SANS Top 25"],
  },
];

export const reports = [
  { id: "RPT-001", title: "Monthly Security Assessment — January 2026", date: "2026-01-31", scope: "Combined", severity: { high: 3, medium: 10, low: 25 }, summary: "Overall security posture improved. Two critical infrastructure findings resolved. Code security findings decreased by 15%." },
  { id: "RPT-002", title: "Infrastructure Security Report", date: "2026-01-15", scope: "Infrastructure", severity: { high: 1, medium: 4, low: 8 }, summary: "Network segmentation review completed. One high-severity finding in firewall configuration addressed." },
  { id: "RPT-003", title: "Code Security Review — Backend", date: "2026-02-05", scope: "Code", severity: { high: 2, medium: 5, low: 12 }, summary: "SAST analysis revealed 2 high-severity SQL injection risks in the API layer. Remediation guidance provided." },
  { id: "RPT-004", title: "Web Application Penetration Test", date: "2026-01-20", scope: "Web", severity: { high: 0, medium: 2, low: 6 }, summary: "No critical vulnerabilities found. Two medium-severity XSS findings in form handling." },
];

export const incidents = [
  { id: "INC-001", title: "Exposed API Key in Public Repository", severity: "High", status: "Resolved", created: "2026-01-28 14:30", resolved: "2026-01-28 16:00", notes: "API key rotated and repository secrets scanner enabled. Developer training scheduled." },
  { id: "INC-002", title: "Unusual Login Attempts Detected", severity: "Medium", status: "Investigating", created: "2026-02-05 09:15", resolved: null, notes: "Monitoring increased. Rate limiting applied. Awaiting client confirmation on suspicious IP range." },
  { id: "INC-003", title: "Outdated TLS Configuration", severity: "Low", status: "Open", created: "2026-02-06 08:00", resolved: null, notes: "TLS 1.0/1.1 still enabled on staging server. Recommended upgrade to TLS 1.3." },
];

export const dashboardStats = {
  securityScore: 78,
  riskSummary: { high: 3, medium: 10, low: 25 },
  lastScanDate: "2026-02-05",
  lastReportDate: "2026-02-05",
  activeIncidents: 2,
  assetsMonitored: 6,
  scansThisMonth: 12,
};

export const securityScoreTrend = [
  { month: "Sep", score: 62 },
  { month: "Oct", score: 65 },
  { month: "Nov", score: 70 },
  { month: "Dec", score: 68 },
  { month: "Jan", score: 74 },
  { month: "Feb", score: 78 },
];

export const severityDistribution = [
  { name: "High", value: 3, fill: "hsl(var(--destructive))" },
  { name: "Medium", value: 10, fill: "hsl(var(--warning))" },
  { name: "Low", value: 25, fill: "hsl(var(--primary))" },
];

export const scanHistory = [
  { date: "Jan 6", infra: 2, web: 1, code: 3 },
  { date: "Jan 13", infra: 1, web: 2, code: 2 },
  { date: "Jan 20", infra: 3, web: 1, code: 4 },
  { date: "Jan 27", infra: 1, web: 3, code: 2 },
  { date: "Feb 3", infra: 2, web: 2, code: 3 },
  { date: "Feb 6", infra: 1, web: 1, code: 1 },
];
