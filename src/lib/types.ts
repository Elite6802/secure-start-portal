export interface SecurityStatus {
  security_score: number;
  risk_summary: { critical: number; moderate: number; low: number };
  assets_monitored: number;
  scans_last_30_days: number;
  open_incidents: number;
  posture_trend?: { month: string; score: number }[];
  compliance_summary?: {
    owasp_top_10?: "Covered" | "Partial" | "Not Assessed";
    iso_27001?: "Covered" | "Partial" | "Not Assessed";
    nist_800_53?: "Covered" | "Partial" | "Not Assessed";
  };
  status_banner: { status: "Green" | "Amber" | "Red"; headline: string; detail: string };
}

export interface Asset {
  id: string;
  organization: string;
  name: string;
  asset_type: string;
  identifier: string;
  risk_level: "critical" | "moderate" | "low";
  last_scanned_at: string | null;
  high_risk_ssrf_authorized?: boolean;
  high_risk_ssrf_authorization_reference?: string;
  high_risk_ssrf_authorization_notes?: string;
  created_at: string;
}

export interface Scan {
  id: string;
  organization: string;
  asset: string;
  scan_type: "web" | "api" | "code" | "network" | "infrastructure" | "cloud";
  status: "pending" | "running" | "completed" | "failed";
  severity_summary: Record<string, number>;
  metadata?: Record<string, unknown>;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface CodeRepository {
  id: string;
  organization: string;
  asset: string;
  repo_url: string;
  language: string;
  created_at: string;
}

export interface CodeFinding {
  id: string;
  repository: string;
  category: "sast" | "dependency" | "secrets";
  severity: "critical" | "high" | "moderate" | "low";
  status?: "open" | "resolved";
  resolved_at?: string | null;
  title: string;
  description: string;
  remediation: string;
  standard_mapping: string[];
  scan_job?: string | null;
  service_request?: string | null;
  secret_type?: string;
  file_path?: string;
  line_number?: number | null;
  masked_value?: string;
  confidence_score?: number | null;
  rationale?: string;
  created_at: string;
}

export interface NetworkAsset {
  id: string;
  organization: string;
  asset: string;
  network_type: "internal" | "external";
  created_at: string;
}

export interface NetworkFinding {
  id: string;
  network_asset: string;
  finding_type: "exposed_service" | "segmentation_risk" | "misconfiguration";
  severity: "critical" | "high" | "moderate" | "low";
  status?: "open" | "resolved";
  resolved_at?: string | null;
  confidence_score?: number | null;
  summary: string;
  recommendation: string;
  rationale?: string;
  evidence?: Record<string, unknown>;
  scan_job?: string | null;
  service_request?: string | null;
  created_at: string;
}

export interface CloudAccount {
  id: string;
  organization: string;
  created_by: string | null;
  provider: "aws" | "azure" | "gcp";
  name: string;
  aws_account_id?: string;
  aws_role_arn?: string;
  aws_external_id?: string;
  azure_tenant_id?: string;
  azure_client_id?: string;
  azure_subscription_id?: string;
  gcp_project_id?: string;
  status: "active" | "disabled" | "error";
  last_validated_at?: string | null;
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface CloudFinding {
  id: string;
  organization: string;
  cloud_account: string;
  asset?: string | null;
  scan_job?: string | null;
  service_request?: string | null;
  title: string;
  severity: "critical" | "high" | "moderate" | "low";
  description: string;
  remediation: string;
  evidence?: Record<string, unknown>;
  compliance?: string[];
  created_at: string;
}

export interface Report {
  id: string;
  organization: string;
  organization_name?: string | null;
  scope: "web" | "code" | "network" | "combined" | "cloud";
  summary: string;
  generated_at: string;
  file_path: string;
  metadata?: Record<string, unknown>;
  service_request?: string | null;
  service_request_type?: string | null;
  scan_job?: string | null;
  scan_job_type?: string | null;
  client_visible?: boolean;
  sent_at?: string | null;
  created_at: string;
}

export interface Incident {
  id: string;
  organization: string;
  severity: "critical" | "high" | "moderate" | "low";
  status: "open" | "investigating" | "resolved";
  description: string;
  detected_at: string;
  resolved_at: string | null;
  created_at: string;
}

export interface ActivityLogItem {
  id: string;
  organization: string;
  organization_name?: string | null;
  user: string | null;
  user_email?: string | null;
  action: string;
  timestamp: string;
  metadata: Record<string, unknown>;
  detail?: string | null;
  created_at: string;
}

export interface Organization {
  id: string;
  name: string;
  industry: string;
  domain: string;
  created_at: string;
  updated_at?: string;
}

export interface UserOrganization {
  id: string;
  organization: string;
  role: string;
  is_primary: boolean;
  created_at: string;
}

export interface UserAccount {
  id: string;
  username: string;
  email: string;
  is_staff: boolean;
  is_active: boolean;
  memberships?: UserOrganization[];
  date_joined: string;
}

export interface ScanRequest {
  id: string;
  organization: string;
  organization_name?: string | null;
  requested_by: string | null;
  requested_by_email?: string | null;
  scan_type: "web" | "api" | "code" | "network" | "infrastructure" | "cloud";
  target: string;
  status: "requested" | "queued" | "in_progress" | "completed" | "rejected" | "failed";
  client_notes: string;
  admin_notes: string;
  asset: string | null;
  asset_name?: string | null;
  repository: string | null;
  repository_url?: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface ServiceRequest {
  id: string;
  organization: string;
  organization_name?: string | null;
  requested_by: string | null;
  requested_by_email?: string | null;
  requested_role: "executive" | "developer" | "security_lead";
  service_type:
    | "CODE_SECRETS_SCAN"
    | "DEPENDENCY_VULN_SCAN"
    | "CODE_COMPLIANCE_SCAN"
    | "CODE_COMPLIANCE_PYTHON"
    | "CODE_COMPLIANCE_HTML"
    | "CODE_COMPLIANCE_CSS"
    | "CODE_COMPLIANCE_JAVASCRIPT"
    | "CODE_COMPLIANCE_REACT"
    | "NETWORK_CONFIGURATION_SCAN"
    | "WEB_EXPOSURE_SCAN"
    | "API_SECURITY_SCAN"
    | "INFRASTRUCTURE_HARDENING_SCAN"
    | "CLOUD_POSTURE_SCAN";
  scope: "repository" | "asset" | "ip_cidr" | "domain" | "cloud" | "";
  repository_url: string;
  asset: string | null;
  asset_name?: string | null;
  ip_cidr: string;
  domain_url: string;
  cloud_account?: string | null;
  ownership_confirmed?: boolean;
  high_risk_ssrf?: boolean;
  authorization_reference?: string;
  authorization_notes?: string;
  justification: string;
  status: "PENDING" | "APPROVED" | "REJECTED" | "RUNNING" | "COMPLETED" | "FAILED";
  approved_by: string | null;
  approved_by_email?: string | null;
  linked_scan_job: string | null;
  linked_scan_job_type?: string | null;
  scan_failure_reason?: string | null;
  report_id?: string | null;
  report_client_visible?: boolean | null;
  report_generated_at?: string | null;
  created_at: string;
  updated_at: string;
}
export interface ScanJob {
  id: string;
  organization: string;
  organization_name?: string | null;
  scan_type: "code" | "network" | "web" | "api" | "infrastructure" | "cloud";
  asset: string | null;
  asset_name?: string | null;
  repository: string | null;
  repository_url?: string | null;
  service_request?: string | null;
  service_request_type?: string | null;
  status: "queued" | "running" | "completed" | "failed";
  started_at: string | null;
  completed_at: string | null;
  failure_reason?: string | null;
  created_by: string | null;
  created_by_email?: string | null;
  duration_seconds?: number | null;
  scope_summary?: string | null;
  assets_scanned?: number | null;
  files_scanned?: number | null;
  findings_summary?: {
    critical: number;
    high: number;
    moderate: number;
    low: number;
  } | null;
  findings_total?: number | null;
  report_id?: string | null;
  report_generated_at?: string | null;
  report_client_visible?: boolean | null;
  created_at: string;
}

export interface AnalystMetrics {
  summary: {
    open_findings: number;
    critical: number;
    high: number;
    moderate: number;
    low: number;
    active_scans: number;
    scan_jobs_running: number;
    reports_ready: number;
    mttr_days: number | null;
    assets_at_risk: number;
  };
  severity_trend: Array<{
    period: string;
    critical: number;
    high: number;
    moderate: number;
    low: number;
  }>;
  scan_volume: Array<{
    period: string;
    code: number;
    web: number;
    network: number;
    infrastructure: number;
  }>;
  finding_breakdown: Array<{ name: string; value: number }>;
  exposure_hotspots: Array<{ label: string; count: number }>;
  report_trend: Array<{ period: string; count: number }>;
}
