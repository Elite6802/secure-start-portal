import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";

export default function SettingsPage() {
  return (
    <div className="max-w-2xl">
      <h1 className="font-display text-2xl font-bold mb-1">Settings</h1>
      <p className="text-sm text-muted-foreground mb-8">Manage your account and notification preferences.</p>

      {/* Company Info */}
      <div className="glass-card rounded-xl p-6 mb-6">
        <h2 className="font-display text-lg font-semibold mb-4">Company Information</h2>
        <div className="space-y-4">
          <div>
            <Label>Company Name</Label>
            <Input value="Acme Corp" readOnly className="mt-1.5 bg-secondary" />
          </div>
          <div>
            <Label>Plan</Label>
            <Input value="Advanced Protection" readOnly className="mt-1.5 bg-secondary" />
          </div>
        </div>
      </div>

      {/* User Profile */}
      <div className="glass-card rounded-xl p-6 mb-6">
        <h2 className="font-display text-lg font-semibold mb-4">User Profile</h2>
        <div className="space-y-4">
          <div>
            <Label>Full Name</Label>
            <Input value="Jane Doe" readOnly className="mt-1.5 bg-secondary" />
          </div>
          <div>
            <Label>Email</Label>
            <Input value="jane@acmecorp.com" readOnly className="mt-1.5 bg-secondary" />
          </div>
          <div>
            <Label>Role</Label>
            <Input value="Security Lead" readOnly className="mt-1.5 bg-secondary" />
          </div>
        </div>
      </div>

      {/* Notifications */}
      <div className="glass-card rounded-xl p-6">
        <h2 className="font-display text-lg font-semibold mb-4">Notification Preferences</h2>
        <div className="space-y-4">
          {[
            { label: "Critical findings alerts", desc: "Get notified immediately for high-severity findings", defaultChecked: true },
            { label: "Scan completion reports", desc: "Receive a summary when scans complete", defaultChecked: true },
            { label: "Monthly security digest", desc: "Monthly overview of your security posture", defaultChecked: true },
            { label: "Incident updates", desc: "Updates on open incident investigations", defaultChecked: false },
          ].map((pref) => (
            <div key={pref.label} className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">{pref.label}</p>
                <p className="text-xs text-muted-foreground">{pref.desc}</p>
              </div>
              <Switch defaultChecked={pref.defaultChecked} />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
