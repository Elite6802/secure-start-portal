import { useEffect, useMemo, useState } from "react";
import { useOutletContext } from "react-router-dom";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { Badge } from "@/components/ui/badge";
import { Code2, GitBranch, Info } from "lucide-react";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { EmptyState } from "@/components/dashboard/EmptyState";
import { RoleRestricted } from "@/components/dashboard/RoleRestricted";
import { ServiceRequestCard } from "@/components/dashboard/ServiceRequestCard";
import { PaginatedResponse, apiRequest, unwrapResults } from "@/lib/api";
import { CodeFinding, CodeRepository } from "@/lib/types";

export default function CodeSecurity() {
  const { accessRole } = useOutletContext<{ role: string; accessRole?: string | null }>();
  const restricted = accessRole ? !["Security Lead", "Developer"].includes(accessRole) : true;
  const [repos, setRepos] = useState<CodeRepository[]>([]);
  const [findings, setFindings] = useState<CodeFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        if (!accessRole || restricted) {
          setLoading(false);
          setError(null);
          return;
        }
        setLoading(true);
        const [reposData, findingsData] = await Promise.all([
          apiRequest<PaginatedResponse<CodeRepository>>("/code-repositories/"),
          apiRequest<PaginatedResponse<CodeFinding>>("/code-findings/"),
        ]);
        setRepos(unwrapResults<CodeRepository>(reposData));
        setFindings(unwrapResults<CodeFinding>(findingsData));
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Failed to load code security data.");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [accessRole, restricted]);

  const findingsByRepo = useMemo(() => {
    const map: Record<string, { critical: number; high: number; moderate: number; low: number; categories: Set<string>; standards: Set<string> }> = {};
    findings.forEach((finding) => {
      if (!map[finding.repository]) {
        map[finding.repository] = { critical: 0, high: 0, moderate: 0, low: 0, categories: new Set(), standards: new Set() };
      }
      map[finding.repository][finding.severity] += 1;
      map[finding.repository].categories.add(finding.category);
      (finding.standard_mapping || []).forEach((item) => map[finding.repository].standards.add(item));
    });
    return map;
  }, [findings]);

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Code Repository Security</h1>
      <p className="text-sm text-muted-foreground mb-8">Security posture across connected repositories, including SAST and dependency coverage.</p>

      <ServiceRequestCard
        title="Request Code Security Review"
        description="Submit a repository for code, dependency, and secrets analysis. The security team will validate access and return findings."
        serviceOptions={[
          { value: "CODE_SECRETS_SCAN", label: "Code Secrets Scan" },
          { value: "DEPENDENCY_VULN_SCAN", label: "Dependency Vulnerability Scan" },
          { value: "CODE_COMPLIANCE_SCAN", label: "Code Standards Compliance" },
        ]}
        targetField="repository_url"
        allowedRoles={["Security Lead", "Developer"]}
        accessRole={accessRole}
        helperText="Requests are reviewed by the platform security team."
        targetPlaceholder="Repository URL or SCM project"
        justificationPlaceholder="Describe the repository, branch, and coverage expectations."
      />

      {!accessRole && <p className="text-sm text-muted-foreground mb-6">Loading access profile...</p>}
      {accessRole && restricted && (
        <RoleRestricted
          title="Code security view restricted"
          description="This view is tailored for engineering and security operations roles. Switch to Developer or Security Lead to review code findings."
        />
      )}
      {accessRole && !restricted && (
        <>
          {loading && <p className="text-sm text-muted-foreground mb-6">Loading code repositories...</p>}
          {error && <p className="text-sm text-destructive mb-6">{error}</p>}

          {repos.length === 0 && !loading ? (
            <EmptyState
              title="No repositories connected"
              description="Once repositories are linked, this view will show scan coverage, findings, and standards alignment. Code visibility reduces release risk and supports secure SDLC audits."
            />
          ) : (
            <div className="space-y-6">
              {repos.map((repo) => {
                const repoFindings = findingsByRepo[repo.id] || { critical: 0, high: 0, moderate: 0, low: 0, categories: new Set(), standards: new Set() };
                const scanTypes = Array.from(repoFindings.categories).map((category) => {
                  if (category === "sast") return "Static Analysis";
                  if (category === "dependency") return "Dependency Check";
                  if (category === "secrets") return "Secrets Detection";
                  return category;
                });
                const standards = Array.from(repoFindings.standards);
                return (
                  <div key={repo.id} className="glass-card rounded-xl p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <div className="rounded-lg bg-primary/10 p-2">
                          <GitBranch className="h-5 w-5 text-primary" />
                        </div>
                        <div>
                          <h3 className="font-display font-semibold">{repo.repo_url}</h3>
                          <p className="text-xs text-muted-foreground">{repo.language || "â€”"} - Connected {repo.created_at?.slice(0, 10)}</p>
                        </div>
                      </div>
                      <Badge variant="outline" className="text-xs">{repo.id}</Badge>
                    </div>

                    <div className="mb-4">
                      <div className="flex items-center gap-2 mb-2">
                        <p className="text-xs font-medium text-muted-foreground">Scan Coverage</p>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <button className="text-muted-foreground hover:text-foreground" aria-label="Scan coverage tooltip">
                              <Info className="h-3.5 w-3.5" />
                            </button>
                          </TooltipTrigger>
                          <TooltipContent className="max-w-xs text-xs">
                            Coverage indicates which automated checks are active for this repository.
                          </TooltipContent>
                        </Tooltip>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {scanTypes.length === 0 ? (
                          <div className="text-xs text-muted-foreground">No scan data yet</div>
                        ) : (
                          scanTypes.map((type) => (
                            <div key={type} className="flex items-center gap-1.5 rounded-md bg-secondary px-2.5 py-1 text-xs">
                              <Code2 className="h-3 w-3 text-primary" />
                              {type}
                            </div>
                          ))
                        )}
                      </div>
                    </div>

                    <div className="mb-4">
                      <p className="text-xs font-medium text-muted-foreground mb-2">Validated Findings</p>
                      <div className="flex gap-2">
                        <SeverityBadge level="Critical" count={repoFindings.critical} />
                        <SeverityBadge level="High" count={repoFindings.high} />
                        <SeverityBadge level="Medium" count={repoFindings.moderate} />
                        <SeverityBadge level="Low" count={repoFindings.low} />
                      </div>
                    </div>

                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <p className="text-xs font-medium text-muted-foreground">Mapped Standards</p>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <button className="text-muted-foreground hover:text-foreground" aria-label="Standards tooltip">
                              <Info className="h-3.5 w-3.5" />
                            </button>
                          </TooltipTrigger>
                          <TooltipContent className="max-w-xs text-xs">
                            Standards mapping helps demonstrate compliance alignment and secure coding maturity.
                          </TooltipContent>
                        </Tooltip>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {standards.length === 0 ? (
                          <span className="text-xs text-muted-foreground">No standards mapped</span>
                        ) : (
                          standards.map((s) => (
                            <Badge key={s} variant="outline" className="text-xs font-normal">{s}</Badge>
                          ))
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}
    </div>
  );
}
