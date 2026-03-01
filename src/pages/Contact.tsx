import { useState } from "react";
import { Shield, CheckCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { MarketingNav } from "@/components/marketing/MarketingNav";
import { Footer } from "@/components/marketing/Footer";
import { apiRequest } from "@/lib/api";

export default function Contact() {
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [form, setForm] = useState({
    name: "",
    email: "",
    company: "",
    message: "",
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await apiRequest("/contact-requests/", {
        method: "POST",
        body: JSON.stringify({
          ...form,
          source_page: "contact",
        }),
      });
      setSubmitted(true);
      setForm({ name: "", email: "", company: "", message: "" });
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to submit request.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="dark min-h-screen bg-background text-foreground">
      <MarketingNav />
      <section className="pt-32 pb-20 md:pt-40 md:pb-28">
        <div className="container mx-auto px-4 max-w-2xl">
          <div className="text-center mb-10">
            <h1 className="font-display text-4xl font-bold">Contact the Security Team</h1>
            <p className="mt-3 text-muted-foreground">Share your security goals and current environment. Response within 1 business day.</p>
          </div>

          {submitted ? (
            <div className="glass-card rounded-2xl p-10 text-center">
              <CheckCircle className="h-12 w-12 text-success mx-auto mb-4" />
              <h2 className="font-display text-2xl font-bold mb-2">Request Received</h2>
              <p className="text-muted-foreground">Thank you for reaching out. Our security team will review your request and respond with next steps.</p>
            </div>
          ) : (
            <div className="grid gap-8 md:grid-cols-[1.2fr_0.8fr]">
              <form onSubmit={handleSubmit} className="glass-card rounded-2xl p-8 space-y-5">
              <div className="flex items-center gap-2 text-xs text-muted-foreground mb-2">
                <Shield className="h-3.5 w-3.5 text-primary" />
                Your information is handled securely and never shared.
              </div>
              <div>
                <Label htmlFor="name">Name</Label>
                <Input
                  id="name"
                  required
                  placeholder="Full name"
                  className="mt-1.5"
                  value={form.name}
                  onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
                />
              </div>
              <div>
                <Label htmlFor="email">Work Email</Label>
                <Input
                  id="email"
                  type="email"
                  required
                  placeholder="you@company.com"
                  className="mt-1.5"
                  value={form.email}
                  onChange={(e) => setForm((prev) => ({ ...prev, email: e.target.value }))}
                />
              </div>
              <div>
                <Label htmlFor="company">Organization</Label>
                <Input
                  id="company"
                  required
                  placeholder="Organization name"
                  className="mt-1.5"
                  value={form.company}
                  onChange={(e) => setForm((prev) => ({ ...prev, company: e.target.value }))}
                />
              </div>
              <div>
                <Label htmlFor="message">Message</Label>
                <Textarea
                  id="message"
                  required
                  placeholder="Describe your environment, goals, and timelines..."
                  rows={4}
                  className="mt-1.5"
                  value={form.message}
                  onChange={(e) => setForm((prev) => ({ ...prev, message: e.target.value }))}
                />
              </div>
              {error && <p className="text-sm text-destructive">{error}</p>}
              <Button type="submit" className="w-full" disabled={submitting}>
                {submitting ? "Submitting..." : "Submit Request"}
              </Button>
              </form>
              <div className="glass-card rounded-2xl p-8">
                <h2 className="font-display text-xl font-bold mb-4">What happens next</h2>
                <ul className="space-y-3 text-sm text-muted-foreground">
                  <li>We review your request within 1 business day.</li>
                  <li>We schedule a discovery call to confirm scope and access.</li>
                  <li>You receive a baseline assessment and prioritized roadmap.</li>
                </ul>
                <div className="mt-6 text-xs text-muted-foreground">
                  Prefer email? Reach us at <span className="text-foreground">security@aegis.ai</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </section>
      <Footer />
    </div>
  );
}
