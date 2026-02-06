import { useState } from "react";
import { Shield, CheckCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { MarketingNav } from "@/components/marketing/MarketingNav";
import { Footer } from "@/components/marketing/Footer";

export default function Contact() {
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitted(true);
  };

  return (
    <div className="dark min-h-screen bg-background text-foreground">
      <MarketingNav />
      <section className="pt-32 pb-20 md:pt-40 md:pb-28">
        <div className="container mx-auto px-4 max-w-lg">
          <div className="text-center mb-10">
            <h1 className="font-display text-4xl font-bold">Get in Touch</h1>
            <p className="mt-3 text-muted-foreground">Tell us about your security needs. We'll respond within 24 hours.</p>
          </div>

          {submitted ? (
            <div className="glass-card rounded-2xl p-10 text-center">
              <CheckCircle className="h-12 w-12 text-success mx-auto mb-4" />
              <h2 className="font-display text-2xl font-bold mb-2">Message Received</h2>
              <p className="text-muted-foreground">Thank you for reaching out. Our security team will review your inquiry and get back to you shortly.</p>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="glass-card rounded-2xl p-8 space-y-5">
              <div className="flex items-center gap-2 text-xs text-muted-foreground mb-2">
                <Shield className="h-3.5 w-3.5 text-primary" />
                Your information is handled securely and never shared.
              </div>
              <div>
                <Label htmlFor="name">Name</Label>
                <Input id="name" required placeholder="Your name" className="mt-1.5" />
              </div>
              <div>
                <Label htmlFor="email">Work Email</Label>
                <Input id="email" type="email" required placeholder="you@company.com" className="mt-1.5" />
              </div>
              <div>
                <Label htmlFor="company">Company</Label>
                <Input id="company" required placeholder="Company name" className="mt-1.5" />
              </div>
              <div>
                <Label htmlFor="message">Message</Label>
                <Textarea id="message" required placeholder="Tell us about your security needs..." rows={4} className="mt-1.5" />
              </div>
              <Button type="submit" className="w-full">Send Message</Button>
            </form>
          )}
        </div>
      </section>
      <Footer />
    </div>
  );
}
