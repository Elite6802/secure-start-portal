import { useEffect, useMemo, useState } from "react";
import { apiRequest, PaginatedResponse, unwrapResults } from "@/lib/api";
import { CloudAccount, Organization } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "@/components/ui/use-toast";

const providerLabels: Record<CloudAccount["provider"], string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "GCP",
};

export default function CloudAccountsAdmin() {
  const [accounts, setAccounts] = useState<CloudAccount[]>([]);
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [secretDrafts, setSecretDrafts] = useState<Record<string, { azure_client_secret?: string; gcp_service_account_json?: string }>>({});

  const [form, setForm] = useState({
    organization: "",
    provider: "aws" as CloudAccount["provider"],
    name: "",
    aws_account_id: "",
    aws_role_arn: "",
    aws_external_id: "",
    azure_tenant_id: "",
    azure_client_id: "",
    azure_subscription_id: "",
    gcp_project_id: "",
  });

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [orgData, accountData] = await Promise.all([
        apiRequest<PaginatedResponse<Organization>>("/internal/organizations/"),
        apiRequest<PaginatedResponse<CloudAccount>>("/cloud-accounts/"),
      ]);
      setOrgs(unwrapResults<Organization>(orgData));
      setAccounts(unwrapResults<CloudAccount>(accountData));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load cloud accounts.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const resetForm = () =>
    setForm({
      organization: "",
      provider: "aws",
      name: "",
      aws_account_id: "",
      aws_role_arn: "",
      aws_external_id: "",
      azure_tenant_id: "",
      azure_client_id: "",
      azure_subscription_id: "",
      gcp_project_id: "",
    });

  const handleCreate = async () => {
    if (!form.organization) {
      setError("Please select an organization.");
      return;
    }
    if (!form.name.trim()) {
      setError("Please provide a display name for the account.");
      return;
    }
    setCreating(true);
    setError(null);
    try {
      const payload: Record<string, string> = {
        organization: form.organization,
        provider: form.provider,
        name: form.name.trim(),
      };
      if (form.provider === "aws") {
        payload.aws_account_id = form.aws_account_id.trim();
        payload.aws_role_arn = form.aws_role_arn.trim();
        if (form.aws_external_id.trim()) {
          payload.aws_external_id = form.aws_external_id.trim();
        }
      }
      if (form.provider === "azure") {
        payload.azure_tenant_id = form.azure_tenant_id.trim();
        payload.azure_client_id = form.azure_client_id.trim();
        payload.azure_subscription_id = form.azure_subscription_id.trim();
      }
      if (form.provider === "gcp") {
        payload.gcp_project_id = form.gcp_project_id.trim();
      }
      await apiRequest("/cloud-accounts/", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      toast({
        title: "Cloud account created",
        description: "Credentials can be added securely after creation.",
      });
      resetForm();
      await load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create cloud account.");
    } finally {
      setCreating(false);
    }
  };

  const handleSaveSecrets = async (account: CloudAccount) => {
    const draft = secretDrafts[account.id] || {};
    if (!draft.azure_client_secret && !draft.gcp_service_account_json) {
      toast({
        title: "No secrets provided",
        description: "Enter an Azure client secret or GCP service account JSON.",
        variant: "destructive",
      });
      return;
    }
    try {
      await apiRequest(`/cloud-accounts/${account.id}/set_secrets/`, {
        method: "POST",
        body: JSON.stringify(draft),
      });
      toast({
        title: "Secrets updated",
        description: "Encrypted credentials have been stored securely.",
      });
      setSecretDrafts((prev) => ({ ...prev, [account.id]: {} }));
      await load();
    } catch (err: unknown) {
      toast({
        title: "Failed to update secrets",
        description: err instanceof Error ? err.message : "Unable to update secrets.",
        variant: "destructive",
      });
    }
  };

  const accountRows = useMemo(() => accounts, [accounts]);
  const orgNameById = useMemo(() => {
    return orgs.reduce<Record<string, string>>((acc, org) => {
      acc[org.id] = org.name;
      return acc;
    }, {});
  }, [orgs]);

  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Cloud Accounts</h1>
      <p className="text-sm text-muted-foreground mb-6">Manage tenant cloud credentials for posture assessments.</p>

      <div className="glass-card rounded-xl p-6 mb-8">
        <h2 className="font-display text-lg font-semibold mb-3">Register Cloud Account</h2>
        {error && <p className="text-sm text-destructive mb-3">{error}</p>}
        <div className="grid gap-3 md:grid-cols-2">
          <div>
            <label className="text-xs font-medium text-muted-foreground">Organization</label>
            <select
              className="mt-1 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
              value={form.organization}
              onChange={(e) => setForm({ ...form, organization: e.target.value })}
            >
              <option value="">Select organization</option>
              {orgs.map((org) => (
                <option key={org.id} value={org.id}>
                  {org.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">Provider</label>
            <select
              className="mt-1 h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
              value={form.provider}
              onChange={(e) => setForm({ ...form, provider: e.target.value as CloudAccount["provider"] })}
            >
              <option value="aws">AWS</option>
              <option value="azure">Azure</option>
              <option value="gcp">GCP</option>
            </select>
          </div>
          <div className="md:col-span-2">
            <label className="text-xs font-medium text-muted-foreground">Display Name</label>
            <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Customer cloud account" />
          </div>
        </div>

        {form.provider === "aws" && (
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <Input placeholder="AWS Account ID" value={form.aws_account_id} onChange={(e) => setForm({ ...form, aws_account_id: e.target.value })} />
            <Input placeholder="AWS Role ARN" value={form.aws_role_arn} onChange={(e) => setForm({ ...form, aws_role_arn: e.target.value })} />
            <Input placeholder="External ID (optional)" value={form.aws_external_id} onChange={(e) => setForm({ ...form, aws_external_id: e.target.value })} />
          </div>
        )}

        {form.provider === "azure" && (
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <Input placeholder="Azure Tenant ID" value={form.azure_tenant_id} onChange={(e) => setForm({ ...form, azure_tenant_id: e.target.value })} />
            <Input placeholder="Azure Client ID" value={form.azure_client_id} onChange={(e) => setForm({ ...form, azure_client_id: e.target.value })} />
            <Input placeholder="Azure Subscription ID" value={form.azure_subscription_id} onChange={(e) => setForm({ ...form, azure_subscription_id: e.target.value })} />
          </div>
        )}

        {form.provider === "gcp" && (
          <div className="mt-4 grid gap-3 md:grid-cols-2">
            <Input placeholder="GCP Project ID" value={form.gcp_project_id} onChange={(e) => setForm({ ...form, gcp_project_id: e.target.value })} />
          </div>
        )}

        <div className="mt-4">
          <Button onClick={handleCreate} disabled={creating}>
            {creating ? "Creating..." : "Create Cloud Account"}
          </Button>
        </div>
      </div>

      <div className="glass-card rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-display text-lg font-semibold">Registered Accounts</h2>
          <Button variant="outline" size="sm" onClick={load}>Refresh</Button>
        </div>
        {loading && <p className="text-sm text-muted-foreground">Loading cloud accounts...</p>}
        {!loading && accountRows.length === 0 && (
          <p className="text-sm text-muted-foreground">No cloud accounts configured yet.</p>
        )}
        {!loading && accountRows.length > 0 && (
          <div className="space-y-4">
            {accountRows.map((account) => (
              <div key={account.id} className="rounded-xl border border-border/60 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <p className="text-xs text-muted-foreground">
                      {providerLabels[account.provider]} · {orgNameById[account.organization] || account.organization}
                    </p>
                    <p className="text-sm font-semibold">{account.name}</p>
                    {account.last_error && <p className="text-xs text-destructive mt-1">{account.last_error}</p>}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs rounded-full px-2 py-1 ${account.status === "active" ? "bg-success/15 text-success" : account.status === "error" ? "bg-destructive/15 text-destructive" : "bg-warning/15 text-warning"}`}>
                      {account.status}
                    </span>
                    <Button variant="outline" size="sm" onClick={() => setExpandedId(expandedId === account.id ? null : account.id)}>
                      {expandedId === account.id ? "Hide Secrets" : "Update Secrets"}
                    </Button>
                  </div>
                </div>

                {expandedId === account.id && (
                  <div className="mt-4 grid gap-3">
                    <Input
                      placeholder="Azure client secret (optional)"
                      value={secretDrafts[account.id]?.azure_client_secret || ""}
                      onChange={(e) =>
                        setSecretDrafts((prev) => ({
                          ...prev,
                          [account.id]: { ...prev[account.id], azure_client_secret: e.target.value },
                        }))
                      }
                    />
                    <Textarea
                      placeholder="GCP service account JSON (optional)"
                      value={secretDrafts[account.id]?.gcp_service_account_json || ""}
                      onChange={(e) =>
                        setSecretDrafts((prev) => ({
                          ...prev,
                          [account.id]: { ...prev[account.id], gcp_service_account_json: e.target.value },
                        }))
                      }
                    />
                    <div className="flex items-center gap-2">
                      <Button size="sm" onClick={() => handleSaveSecrets(account)}>Save Secrets</Button>
                      <Button size="sm" variant="ghost" onClick={() => setExpandedId(null)}>
                        Cancel
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
