import { useEffect, useState } from "react";
import { PaginatedResponse, apiRequest, unwrapResults } from "@/lib/api";
import { Incident } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export default function IncidentsAdmin() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState({
    organization: "",
    severity: "moderate",
    status: "open",
    description: "",
    detected_at: "",
    resolved_at: "",
  });

  const load = async () => {
    setLoading(true);
    const data = await apiRequest<PaginatedResponse<Incident>>("/internal/incidents/");
    setIncidents(unwrapResults<Incident>(data));
    setLoading(false);
  };

  useEffect(() => {
    load().catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load incidents."));
  }, []);

  const handleCreate = async () => {
    setError(null);
    try {
      await apiRequest("/internal/incidents/", {
        method: "POST",
        body: JSON.stringify({
          organization: form.organization || undefined,
          severity: form.severity,
          status: form.status,
          description: form.description,
          detected_at: form.detected_at || new Date().toISOString(),
          resolved_at: form.resolved_at || null,
        }),
      });
      setForm({ organization: "", severity: "moderate", status: "open", description: "", detected_at: "", resolved_at: "" });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create incident.");
    }
  };

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Incidents</h1>
      <p className="text-sm text-muted-foreground mb-6">Cross-tenant incident intake and operational tracking.</p>

      {error && <p className="text-sm text-destructive mb-4">{error}</p>}

      <div className="glass-card rounded-xl p-5 mb-6">
        <div className="grid gap-3 md:grid-cols-2">
          <Input placeholder="Organization UUID" value={form.organization} onChange={(e) => setForm({ ...form, organization: e.target.value })} />
          <Input placeholder="Detected at (YYYY-MM-DDTHH:MM:SSZ)" value={form.detected_at} onChange={(e) => setForm({ ...form, detected_at: e.target.value })} />
          <Select value={form.severity} onValueChange={(value) => setForm({ ...form, severity: value })}>
            <SelectTrigger>
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="moderate">Moderate</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>
          <Select value={form.status} onValueChange={(value) => setForm({ ...form, status: value })}>
            <SelectTrigger>
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="open">Open</SelectItem>
              <SelectItem value="investigating">Investigating</SelectItem>
              <SelectItem value="resolved">Resolved</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="mt-3">
          <Textarea placeholder="Incident description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
        </div>
        <div className="mt-3">
          <Input placeholder="Resolved at (optional)" value={form.resolved_at} onChange={(e) => setForm({ ...form, resolved_at: e.target.value })} />
        </div>
        <div className="mt-4">
          <Button onClick={handleCreate}>Create Incident</Button>
        </div>
      </div>

      <div className="glass-card rounded-xl overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Severity</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Description</TableHead>
              <TableHead>Detected</TableHead>
              <TableHead>Resolved</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={5} className="text-sm text-muted-foreground">Loading incidents...</TableCell>
              </TableRow>
            ) : (
              incidents.map((incident) => (
                <TableRow key={incident.id}>
                  <TableCell className="text-muted-foreground">{incident.severity}</TableCell>
                  <TableCell className="text-muted-foreground">{incident.status}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">{incident.description}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{incident.detected_at}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{incident.resolved_at || "â€”"}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
