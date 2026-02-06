import { codeRepos } from "@/data/mockData";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { Badge } from "@/components/ui/badge";
import { Code2, GitBranch } from "lucide-react";

export default function CodeSecurity() {
  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Code Security</h1>
      <p className="text-sm text-muted-foreground mb-8">Security analysis across your connected code repositories.</p>

      <div className="space-y-6">
        {codeRepos.map((repo) => (
          <div key={repo.id} className="glass-card rounded-xl p-6">
            <div className="flex items-start justify-between mb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-primary/10 p-2">
                  <GitBranch className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <h3 className="font-display font-semibold">{repo.name}</h3>
                  <p className="text-xs text-muted-foreground">{repo.language} · Last scanned {repo.lastScan}</p>
                </div>
              </div>
              <Badge variant="outline" className="text-xs">{repo.id}</Badge>
            </div>

            {/* Scan types */}
            <div className="mb-4">
              <p className="text-xs font-medium text-muted-foreground mb-2">Scan Coverage</p>
              <div className="flex flex-wrap gap-2">
                {repo.scanTypes.map((type) => (
                  <div key={type} className="flex items-center gap-1.5 rounded-md bg-secondary px-2.5 py-1 text-xs">
                    <Code2 className="h-3 w-3 text-primary" />
                    {type}
                  </div>
                ))}
              </div>
            </div>

            {/* Severity breakdown */}
            <div className="mb-4">
              <p className="text-xs font-medium text-muted-foreground mb-2">Findings</p>
              <div className="flex gap-2">
                <SeverityBadge level="Critical" count={repo.findings.critical} />
                <SeverityBadge level="High" count={repo.findings.high} />
                <SeverityBadge level="Medium" count={repo.findings.medium} />
                <SeverityBadge level="Low" count={repo.findings.low} />
              </div>
            </div>

            {/* Standards */}
            <div>
              <p className="text-xs font-medium text-muted-foreground mb-2">Mapped Standards</p>
              <div className="flex flex-wrap gap-2">
                {repo.standards.map((s) => (
                  <Badge key={s} variant="outline" className="text-xs font-normal">{s}</Badge>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
