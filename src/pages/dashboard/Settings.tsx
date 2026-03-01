import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";

export default function SettingsPage() {
  return (
    <div className="max-w-2xl">
      <h1 className="font-display text-2xl font-bold mb-1">Account Settings</h1>
      <p className="text-sm text-muted-foreground mb-8">Manage organization details, user profile, and notification preferences.</p>

      {/* Company Info */}
      <div className="glass-card rounded-xl p-6 mb-6">
        <h2 className="font-display text-lg font-semibold mb-4">Organization Profile</h2>
        <div className="space-y-4">
          <div>
            <Label>Organization Name</Label>
            <Input value="Acme Corp" readOnly className="mt-1.5 bg-secondary" />
          </div>
          <div>
            <Label>Subscription Tier</Label>
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
            <Label>Primary Role</Label>
            <Input value="Security Lead" readOnly className="mt-1.5 bg-secondary" />
          </div>
        </div>
      </div>

      {/* Notifications */}
      <div className="glass-card rounded-xl p-6">
        <h2 className="font-display text-lg font-semibold mb-4">Notification Preferences</h2>
        <div className="space-y-4">
          {[
            { label: "Critical findings alerts", desc: "Immediate notification for critical or high-impact findings.", defaultChecked: true },
            { label: "Scan completion reports", desc: "Summary report when automated scans complete.", defaultChecked: true },
            { label: "Monthly security digest", desc: "Monthly overview of posture, coverage, and risk trends.", defaultChecked: true },
            { label: "Incident updates", desc: "Updates on active incident investigations and status changes.", defaultChecked: false },
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
