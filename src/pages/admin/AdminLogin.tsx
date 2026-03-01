import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { login, apiRequest } from "@/lib/api";

export default function AdminLogin() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const form = e.target as HTMLFormElement;
      const formData = new FormData(form);
      const username = String(formData.get("username"));
      const password = String(formData.get("password"));
      await login(username, password);
      await apiRequest("/internal/organizations/");
      navigate("/admin");
    } catch (err) {
      const message = err instanceof Error ? err.message : "Login failed.";
      const normalized = message.toLowerCase();
      if (normalized.includes("access restricted") || normalized.includes("permission")) {
        setError("Admin access required. Contact the platform owner.");
      } else if (normalized.includes("no active account")) {
        setError("Invalid username or password. Please try again.");
      } else if (normalized.includes("credentials") || normalized.includes("password")) {
        setError("Credentials do not match. Please try again.");
      } else {
        setError("Login failed. Please verify your credentials.");
      }
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="dark min-h-screen bg-background text-foreground flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-2 mb-4">
            <Shield className="h-8 w-8 text-primary" />
            <span className="font-display text-2xl font-bold">Aegis Admin</span>
          </div>
          <h1 className="font-display text-2xl font-bold">Platform Operations</h1>
          <p className="mt-2 text-sm text-muted-foreground">Sign in to manage organizations, users, and platform activity.</p>
        </div>

        <form onSubmit={handleSubmit} className="glass-card rounded-2xl p-8 space-y-5">
          <div>
            <Label htmlFor="username">Admin Username</Label>
            <Input id="username" name="username" type="text" required placeholder="admin" className="mt-1.5" />
          </div>
          <div>
            <Label htmlFor="password">Password</Label>
            <Input id="password" name="password" type="password" required placeholder="********" className="mt-1.5" />
          </div>
          <Button type="submit" className="w-full" disabled={loading}>
            {loading ? "Signing in..." : "Sign In"}
          </Button>
          {error && <p className="text-xs text-destructive text-center">{error}</p>}
          <p className="text-xs text-center text-muted-foreground mt-4">
            Access limited to platform operators and SOC administrators.
          </p>
        </form>
      </div>
    </div>
  );
}
