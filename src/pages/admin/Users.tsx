import { useEffect, useState } from "react";
import { PaginatedResponse, apiRequest, unwrapResults } from "@/lib/api";
import { Organization, UserAccount, UserOrganization } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const ROLE_OPTIONS = [
  { value: "security_lead", label: "Security Lead" },
  { value: "developer", label: "Developer" },
  { value: "executive", label: "Executive" },
  { value: "soc_admin", label: "SOC Admin" },
];

const getPrimaryMembership = (memberships?: UserOrganization[]) => {
  if (!memberships || memberships.length === 0) return null;
  return memberships.find((m) => m.is_primary) || memberships[0];
};

export default function UsersAdmin() {
  const [users, setUsers] = useState<UserAccount[]>([]);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState({
    username: "",
    email: "",
    password: "",
    is_staff: false,
    role: "developer",
    organization: "",
  });
  const [error, setError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState({ username: "", email: "", password: "", role: "developer" });

  const load = async () => {
    setLoading(true);
    const [userData, orgData] = await Promise.all([
      apiRequest<PaginatedResponse<UserAccount>>("/internal/users/"),
      apiRequest<PaginatedResponse<Organization>>("/internal/organizations/"),
    ]);
    setUsers(unwrapResults<UserAccount>(userData));
    setOrganizations(unwrapResults<Organization>(orgData));
    setLoading(false);
  };

  useEffect(() => {
    load().catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load users."));
  }, []);

  const handleCreate = async () => {
    setError(null);
    try {
      await apiRequest("/internal/users/", {
        method: "POST",
        body: JSON.stringify({
          username: form.username,
          email: form.email,
          password: form.password || undefined,
          is_staff: form.is_staff,
          role: form.role,
          organization: form.organization || undefined,
        }),
      });
      setForm({ username: "", email: "", password: "", is_staff: false, role: "developer", organization: "" });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create user.");
    }
  };

  const handleDelete = async (id: string) => {
    setError(null);
    try {
      await apiRequest(`/internal/users/${id}/`, { method: "DELETE" });
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to delete user.");
    }
  };

  const startEdit = (user: UserAccount) => {
    const membership = getPrimaryMembership(user.memberships);
    setEditingId(user.id);
    setEditForm({
      username: user.username,
      email: user.email,
      password: "",
      role: membership?.role || "developer",
    });
  };

  const cancelEdit = () => {
    setEditingId(null);
    setEditForm({ username: "", email: "", password: "", role: "developer" });
  };

  const handleSave = async (user: UserAccount) => {
    setError(null);
    const membership = getPrimaryMembership(user.memberships);
    try {
      await apiRequest(`/internal/users/${user.id}/`, {
        method: "PATCH",
        body: JSON.stringify({
          username: editForm.username,
          email: editForm.email,
          password: editForm.password || undefined,
          role: editForm.role,
          organization: membership?.organization,
          is_primary: membership ? true : undefined,
        }),
      });
      await load();
      cancelEdit();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to update user.");
    }
  };

  const organizationNameById = organizations.reduce<Record<string, string>>((acc, org) => {
    acc[org.id] = org.name;
    return acc;
  }, {});

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Users</h1>
      <p className="text-sm text-muted-foreground mb-6">Manage internal users and staff access.</p>

      {error && <p className="text-sm text-destructive mb-4">{error}</p>}

      <div className="glass-card rounded-xl p-5 mb-6">
        <div className="grid gap-3 md:grid-cols-4">
          <Input placeholder="Username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
          <Input placeholder="Email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          <Input placeholder="Password" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <select
            className="h-10 rounded-md border border-input bg-background px-3 text-sm"
            value={form.role}
            onChange={(e) => setForm({ ...form, role: e.target.value })}
          >
            {ROLE_OPTIONS.map((role) => (
              <option key={role.value} value={role.value}>{role.label}</option>
            ))}
          </select>
        </div>
        <div className="mt-3">
          <select
            className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
            value={form.organization}
            onChange={(e) => setForm({ ...form, organization: e.target.value })}
          >
            <option value="">Select organization</option>
            {organizations.map((org) => (
              <option key={org.id} value={org.id}>{org.name}</option>
            ))}
          </select>
        </div>
        <div className="mt-4 flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            <input
              type="checkbox"
              checked={form.is_staff}
              onChange={(e) => setForm({ ...form, is_staff: e.target.checked })}
            />
            Staff access
          </label>
          <Button onClick={handleCreate} disabled={!form.organization}>Create User</Button>
        </div>
      </div>

      <div className="glass-card rounded-xl overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Username</TableHead>
              <TableHead>Email</TableHead>
              <TableHead>Organization</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Staff</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Password Reset</TableHead>
              <TableHead>Joined</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={9} className="text-sm text-muted-foreground">Loading users...</TableCell>
              </TableRow>
            ) : (
              users.map((user) => (
                <TableRow key={user.id}>
                  {editingId === user.id ? (
                    <>
                      <TableCell className="font-medium">
                        <Input value={editForm.username} onChange={(e) => setEditForm({ ...editForm, username: e.target.value })} />
                      </TableCell>
                      <TableCell>
                        <Input value={editForm.email} onChange={(e) => setEditForm({ ...editForm, email: e.target.value })} />
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {organizationNameById[getPrimaryMembership(user.memberships)?.organization || ""] || "—"}
                      </TableCell>
                      <TableCell>
                        <select
                          className="h-9 w-full rounded-md border border-input bg-background px-2 text-xs"
                          value={editForm.role}
                          onChange={(e) => setEditForm({ ...editForm, role: e.target.value })}
                        >
                          {ROLE_OPTIONS.map((role) => (
                            <option key={role.value} value={role.value}>{role.label}</option>
                          ))}
                        </select>
                      </TableCell>
                      <TableCell className="text-muted-foreground">{user.is_staff ? "Yes" : "No"}</TableCell>
                      <TableCell className="text-muted-foreground">{user.is_active ? "Active" : "Inactive"}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        <Input
                          placeholder="New password (optional)"
                          type="password"
                          value={editForm.password}
                          onChange={(e) => setEditForm({ ...editForm, password: e.target.value })}
                        />
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{user.date_joined?.slice(0, 10)}</TableCell>
                      <TableCell className="text-right space-x-2">
                        <Button size="sm" onClick={() => handleSave(user)}>Save</Button>
                        <Button variant="outline" size="sm" onClick={cancelEdit}>Cancel</Button>
                      </TableCell>
                    </>
                  ) : (
                    <>
                      <TableCell className="font-medium">{user.username}</TableCell>
                      <TableCell className="text-muted-foreground">{user.email}</TableCell>
                      <TableCell className="text-muted-foreground">
                        {organizationNameById[getPrimaryMembership(user.memberships)?.organization || ""] || "—"}
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {ROLE_OPTIONS.find((role) => role.value === getPrimaryMembership(user.memberships)?.role)?.label || "—"}
                      </TableCell>
                      <TableCell className="text-muted-foreground">{user.is_staff ? "Yes" : "No"}</TableCell>
                      <TableCell className="text-muted-foreground">{user.is_active ? "Active" : "Inactive"}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">—</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{user.date_joined?.slice(0, 10)}</TableCell>
                      <TableCell className="text-right space-x-2">
                        <Button variant="outline" size="sm" onClick={() => startEdit(user)}>Edit</Button>
                        <Button variant="outline" size="sm" onClick={() => handleDelete(user.id)}>Delete</Button>
                      </TableCell>
                    </>
                  )}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
