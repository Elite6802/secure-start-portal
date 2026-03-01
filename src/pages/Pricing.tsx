import { Link } from "react-router-dom";
import { CheckCircle, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { MarketingNav } from "@/components/marketing/MarketingNav";
import { Footer } from "@/components/marketing/Footer";

const plans = [
  {
    name: "Core Protection",
    price: "KES 75,000",
    priceUsd: "~$580 USD",
    period: "/month",
    desc: "Essential coverage for early-stage teams with foundational security needs.",
    idealFor: "Startups, NGOs, and small teams launching secure programs",
    features: [
      "Infrastructure vulnerability scanning",
      "Web application security testing",
      "Baseline code security analysis (SAST)",
      "Monthly security reports",
      "Email support and remediation guidance",
      "Up to 10 monitored assets",
    ],
    highlighted: false,
  },
  {
    name: "Advanced Protection",
    price: "KES 180,000",
    priceUsd: "~$1,400 USD",
    period: "/month",
    desc: "Comprehensive coverage for scaling companies and regulated institutions.",
    idealFor: "Regulated, high-growth, or enterprise security teams",
    features: [
      "Everything in Core Protection",
      "Continuous monitoring and alerting",
      "Advanced SAST and dependency scanning",
      "Secrets detection & container scanning",
      "Cloud security posture management",
      "Compliance readiness (OWASP, PCI DSS)",
      "Priority incident response",
      "Dedicated security advisor",
      "Unlimited monitored assets",
    ],
    highlighted: true,
  },
];

const faqs = [
  {
    q: "Can I upgrade plans later?",
    a: "Yes. You can move between plans at any time as your coverage needs evolve.",
  },
  {
    q: "What does onboarding include?",
    a: "Asset inventory setup, access validation, and a baseline assessment within days.",
  },
  {
    q: "Do you offer custom plans?",
    a: "Yes. We can tailor SLAs, reporting depth, and coverage to your environment.",
  },
];

export default function Pricing() {
  return (
    <div className="dark min-h-screen bg-background text-foreground">
      <MarketingNav />
      <section className="pt-32 pb-20 md:pt-40 md:pb-28">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h1 className="font-display text-4xl font-bold md:text-5xl">Simple, Transparent Pricing</h1>
            <p className="mt-4 text-muted-foreground max-w-xl mx-auto">
              Choose the plan that fits your security needs. Base pricing displayed in KES - final billing currency depends on client location.
            </p>
          </div>

          <div className="grid gap-8 md:grid-cols-2 max-w-4xl mx-auto">
            {plans.map((plan) => (
              <div
                key={plan.name}
                className={`glass-card rounded-2xl p-8 flex flex-col ${
                  plan.highlighted ? "border-primary/40 glow-primary" : ""
                }`}
              >
                {plan.highlighted && (
                  <div className="inline-flex self-start rounded-full bg-primary/15 px-3 py-1 text-xs font-semibold text-primary mb-4">
                    Most Popular
                  </div>
                )}
                <h3 className="font-display text-2xl font-bold">{plan.name}</h3>
                <p className="mt-2 text-sm text-muted-foreground">{plan.desc}</p>
                <p className="mt-2 text-xs text-muted-foreground">Ideal for: {plan.idealFor}</p>
                <div className="mt-6">
                  <span className="font-display text-4xl font-bold">{plan.price}</span>
                  <span className="text-muted-foreground text-sm">{plan.period}</span>
                </div>
                <p className="text-xs text-muted-foreground mt-1">{plan.priceUsd}</p>
                <ul className="mt-8 space-y-3 flex-1">
                  {plan.features.map((feature) => (
                    <li key={feature} className="flex items-start gap-2 text-sm text-muted-foreground">
                      <CheckCircle className="h-4 w-4 text-success mt-0.5 shrink-0" />
                      {feature}
                    </li>
                  ))}
                </ul>
                <Link to="/contact" className="mt-8">
                  <Button className="w-full gap-2" variant={plan.highlighted ? "default" : "outline"}>
                    Request Baseline Assessment
                    <ArrowRight className="h-4 w-4" />
                  </Button>
                </Link>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="pb-20 md:pb-28">
        <div className="container mx-auto px-4">
          <div className="mx-auto max-w-4xl rounded-2xl border border-border bg-secondary/10 p-8 text-center">
            <h2 className="font-display text-2xl font-bold mb-3">Security Promise</h2>
            <p className="text-sm text-muted-foreground mb-6">
              All scans are consent-based, non-destructive, and fully auditable. We protect your data with least-privilege access,
              encrypted storage, and detailed evidence trails.
            </p>
            <div className="grid gap-4 md:grid-cols-3 text-sm text-muted-foreground">
              <div className="glass-card rounded-xl p-4">Encrypted data handling</div>
              <div className="glass-card rounded-xl p-4">Audit-ready reporting</div>
              <div className="glass-card rounded-xl p-4">Strict scope validation</div>
            </div>
          </div>
        </div>
      </section>

      <section className="pb-20 md:pb-28">
        <div className="container mx-auto px-4">
          <div className="text-center mb-10">
            <h2 className="font-display text-2xl font-bold md:text-3xl">Pricing FAQs</h2>
            <p className="mt-3 text-muted-foreground">Transparent answers for procurement and security teams.</p>
          </div>
          <div className="grid gap-6 md:grid-cols-3">
            {faqs.map((faq) => (
              <div key={faq.q} className="glass-card rounded-xl p-6">
                <h3 className="font-display font-semibold mb-2">{faq.q}</h3>
                <p className="text-sm text-muted-foreground">{faq.a}</p>
              </div>
            ))}
          </div>
        </div>
      </section>
      <Footer />
    </div>
  );
}
