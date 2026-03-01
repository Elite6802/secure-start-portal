import { useEffect, useState } from "react";
import { PaginatedResponse, apiRequest, unwrapResults } from "@/lib/api";
import { ScanJob } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { toast } from "@/components/ui/use-toast";

export default function ScanJobsAdmin() {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({
    organization: "",
    scan_type: "web",
    asset: "",
    repository: "",
  });

  const statusLabels: Record<string, string> = {
    queued: "Pending",
    running: "In Progress",
    completed: "Completed",
    failed: "Failed",
  };

  const formatDuration = (seconds?: number | null) => {
    if (!seconds && seconds !== 0) return "-";
    const minutes = Math.floor(seconds / 60);
    const remaining = seconds % 60;
    if (minutes === 0) return `${remaining}s`;
    return `${minutes}m ${remaining}s`;
  };

  const load = async () => {
    setLoading(true);
    const data = await apiRequest<PaginatedResponse<ScanJob>>("/internal/scan-jobs/");
    setJobs(unwrapResults<ScanJob>(data));
    setLoading(false);
  };

  useEffect(() => {
    load().catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load scan jobs."));
  }, []);

  const handleCreate = async () => {
    setError(null);
    try {
      await apiRequest("/internal/scan-jobs/", {
        method: "POST",
        body: JSON.stringify({
          organization: form.organization || undefined,
          scan_type: form.scan_type,
          asset: form.asset || null,
          repository: form.repository || null,
        }),
      });
      setForm({ organization: "", scan_type: "web", asset: "", repository: "" });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create scan job.");
    }
  };

  const handleRescan = async (jobId: string) => {
    setError(null);
    try {
      await apiRequest(`/internal/scan-jobs/${jobId}/rescan/`, { method: "POST" });
      await load();
      toast({
        title: "Scan rescanned",
        description: "The failed scan job is now pending and has been queued again.",
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to rescan job.";
      setError(message);
      toast({
        title: "Rescan failed",
        description: message,
        variant: "destructive",
      });
    }
  };

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Scan Jobs</h1>
      <p className="text-sm text-muted-foreground mb-6">Queue and monitor internal scan jobs across tenants.</p>

      {error && <p className="text-sm text-destructive mb-4">{error}</p>}

      <div className="glass-card rounded-xl p-5 mb-6">
        <div className="grid gap-3 md:grid-cols-4">
          <Input placeholder="Organization UUID" value={form.organization} onChange={(e) => setForm({ ...form, organization: e.target.value })} />
          <Select value={form.scan_type} onValueChange={(value) => setForm({ ...form, scan_type: value })}>
            <SelectTrigger>
              <SelectValue placeholder="Scan type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="web">Web</SelectItem>
              <SelectItem value="api">API</SelectItem>
              <SelectItem value="code">Code</SelectItem>
              <SelectItem value="network">Network</SelectItem>
              <SelectItem value="infrastructure">Infrastructure</SelectItem>
            </SelectContent>
          </Select>
          <Input placeholder="Asset UUID" value={form.asset} onChange={(e) => setForm({ ...form, asset: e.target.value })} />
          <Input placeholder="Repository UUID" value={form.repository} onChange={(e) => setForm({ ...form, repository: e.target.value })} />
        </div>
        <div className="mt-4">
          <Button onClick={handleCreate}>Create Scan Job</Button>
        </div>
      </div>

      <div className="glass-card rounded-xl overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Scan Type</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Organization</TableHead>
              <TableHead>Scope</TableHead>
              <TableHead>Assets</TableHead>
              <TableHead>Files</TableHead>
              <TableHead>Findings</TableHead>
              <TableHead>Started</TableHead>
              <TableHead>Completed</TableHead>
              <TableHead>Duration</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={11} className="text-sm text-muted-foreground">Loading scan jobs...</TableCell>
              </TableRow>
            ) : (
              jobs.map((job) => (
                <TableRow key={job.id}>
                  <TableCell className="font-medium">{job.scan_type}</TableCell>
                  <TableCell>
                    <StatusBadge status={statusLabels[job.status] || job.status} />
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{job.organization_name || job.organization}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{job.scope_summary || job.asset_name || job.repository_url || "-"}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{job.assets_scanned ?? "-"}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{job.files_scanned ?? "-"}</TableCell>
                  <TableCell>
                    {job.status === "completed" ? (
                      <div className="space-y-1">
                        <div className="flex gap-1.5">
                          <SeverityBadge level="Critical" count={job.findings_summary?.critical || 0} />
                          <SeverityBadge level="High" count={job.findings_summary?.high || 0} />
                          <SeverityBadge level="Medium" count={job.findings_summary?.moderate || 0} />
                          <SeverityBadge level="Low" count={job.findings_summary?.low || 0} />
                        </div>
                        <p className="text-[11px] text-muted-foreground">
                          {job.findings_total ?? 0} findings
                        </p>
                      </div>
                    ) : job.status === "failed" ? (
                      <p className="text-xs text-destructive">{job.failure_reason || "Failed"}</p>
                    ) : (
                      <span className="text-xs text-muted-foreground">Not available</span>
                    )}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{job.started_at || "-"}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{job.completed_at || "-"}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{formatDuration(job.duration_seconds)}</TableCell>
                  <TableCell className="text-right">
                    {job.status === "failed" ? (
                      <Button size="sm" variant="outline" onClick={() => handleRescan(job.id)}>
                        Rescan
                      </Button>
                    ) : (
                      <span className="text-xs text-muted-foreground">-</span>
                    )}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
