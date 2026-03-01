import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { PaginatedResponse, apiRequest, unwrapResults } from "@/lib/api";
import { Organization } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export default function OrganizationsAdmin() {
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState({ name: "", industry: "", domain: "" });
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    const data = await apiRequest<PaginatedResponse<Organization>>("/internal/organizations/");
    setOrgs(unwrapResults<Organization>(data));
    setLoading(false);
  };

  useEffect(() => {
    load().catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load organizations."));
  }, []);

  const handleCreate = async () => {
    setError(null);
    try {
      await apiRequest("/internal/organizations/", {
        method: "POST",
        body: JSON.stringify(form),
      });
      setForm({ name: "", industry: "", domain: "" });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create organization.");
    }
  };

  const handleDelete = async (id: string) => {
    setError(null);
    try {
      await apiRequest(`/internal/organizations/${id}/`, { method: "DELETE" });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to delete organization.");
    }
  };

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Organizations</h1>
      <p className="text-sm text-muted-foreground mb-6">Manage tenant organizations across the platform.</p>

      {error && <p className="text-sm text-destructive mb-4">{error}</p>}

      <div className="glass-card rounded-xl p-5 mb-6">
        <div className="grid gap-3 md:grid-cols-3">
          <Input placeholder="Organization name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <Input placeholder="Industry" value={form.industry} onChange={(e) => setForm({ ...form, industry: e.target.value })} />
          <Input placeholder="Domain" value={form.domain} onChange={(e) => setForm({ ...form, domain: e.target.value })} />
        </div>
        <div className="mt-4">
          <Button onClick={handleCreate}>Create Organization</Button>
        </div>
      </div>

      <div className="glass-card rounded-xl overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Industry</TableHead>
              <TableHead>Domain</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={5} className="text-sm text-muted-foreground">Loading organizations...</TableCell>
              </TableRow>
            ) : (
              orgs.map((org) => (
                <TableRow key={org.id}>
                  <TableCell className="font-medium">{org.name}</TableCell>
                  <TableCell className="text-muted-foreground">{org.industry || "â€”"}</TableCell>
                  <TableCell className="text-muted-foreground">{org.domain || "â€”"}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{org.created_at?.slice(0, 10)}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-2">
                      <Button asChild variant="secondary" size="sm">
                        <Link to={`/admin/organizations/${org.id}`}>View</Link>
                      </Button>
                      <Button variant="outline" size="sm" onClick={() => handleDelete(org.id)}>Delete</Button>
                    </div>
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
