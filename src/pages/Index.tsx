import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Shield, Server, Globe, Cloud, Code, ArrowRight, CheckCircle, ClipboardCheck, BarChart3, FileSearch, ShieldCheck, Lock, Eye } from "lucide-react";
import { Button } from "@/components/ui/button";
import { MarketingNav } from "@/components/marketing/MarketingNav";
import { Footer } from "@/components/marketing/Footer";
import safaritekLogo from "@/assets/clients/safaritek.svg";
import blueledgerLogo from "@/assets/clients/blueledger.svg";
import kifaruHealthLogo from "@/assets/clients/kifaru-health.svg";
import vertexPayLogo from "@/assets/clients/vertexpay.svg";
import civicStackLogo from "@/assets/clients/civicstack.svg";
import novaEduLogo from "@/assets/clients/novaedu.svg";

const fadeUp = {
  hidden: { opacity: 0, y: 20 },
  visible: (i: number) => ({ opacity: 1, y: 0, transition: { delay: i * 0.1, duration: 0.5 } }),
};

const protectAreas = [
  { icon: Server, title: "Infrastructure and Networks", desc: "Continuous monitoring of servers, firewalls, and network controls." },
  { icon: Globe, title: "Web and APIs", desc: "Vulnerability assessments for web applications and API endpoints." },
  { icon: Cloud, title: "Cloud Environments", desc: "Security posture management across AWS, Azure, and GCP." },
  { icon: Code, title: "Code and Software Supply Chain", desc: "Static analysis, dependency scanning, and secure coding enforcement." },
];

const howItWorks = [
  { step: "01", icon: ClipboardCheck, title: "Asset Onboarding", desc: "Register infrastructure, applications, and code repositories." },
  { step: "02", icon: FileSearch, title: "Automated Scans", desc: "Continuous security scanning across all registered assets." },
  { step: "03", icon: Eye, title: "Reviews and Compliance", desc: "Code reviews, compliance checks, and standards validation." },
  { step: "04", icon: BarChart3, title: "Reporting and Guidance", desc: "Actionable reports with prioritized remediation steps." },
];

const outcomes = [
  { value: "48 hrs", label: "Average baseline assessment turnaround" },
  { value: "30%", label: "Reduction in critical exposures after first quarter" },
  { value: "24/7", label: "Monitoring and alert coverage for critical assets" },
];

const trustSignals = [
  { title: "SOC-ready workflows", desc: "Audit trails, role-based access, and evidence capture built in." },
  { title: "Compliance alignment", desc: "Mappings for OWASP, ISO 27001, and NIST controls." },
  { title: "Zero-exploitation policy", desc: "Safe, non-destructive validation with clear consent boundaries." },
];

const clientLogos = [
  { name: "Safaritek", src: safaritekLogo },
  { name: "BlueLedger", src: blueledgerLogo },
  { name: "Kifaru Health", src: kifaruHealthLogo },
  { name: "VertexPay", src: vertexPayLogo },
  { name: "CivicStack", src: civicStackLogo },
  { name: "NovaEdu", src: novaEduLogo },
];

const faqs = [
  {
    q: "How do you handle sensitive data and credentials?",
    a: "We never store customer secrets in reports. Credentials remain in your control and can be rotated at any time. All access is auditable.",
  },
  {
    q: "Can you scan external assets?",
    a: "Yes, but only with explicit client authorization. We use safe, non-intrusive validation techniques.",
  },
  {
    q: "How long does onboarding take?",
    a: "Most teams complete onboarding in 1–3 days depending on asset inventory size.",
  },
  {
    q: "Do you provide remediation guidance?",
    a: "Every report includes prioritized remediation actions and role-specific recommendations.",
  },
];

export default function Index() {
  return (
    <div className="dark min-h-screen bg-background text-foreground">
      <MarketingNav />

      {/* Hero */}
      <section className="relative overflow-hidden pt-32 pb-20 md:pt-44 md:pb-32">
        <div className="absolute inset-0 bg-gradient-to-b from-primary/5 to-transparent" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full bg-primary/5 blur-[100px]" />
        <div className="container relative mx-auto px-4 text-center">
          <motion.div initial="hidden" animate="visible" variants={fadeUp} custom={0}>
            <div className="inline-flex items-center gap-2 rounded-full border border-border bg-secondary/50 px-4 py-1.5 text-xs font-medium text-muted-foreground mb-8">
              <ShieldCheck className="h-3.5 w-3.5 text-primary" />
              Managed Cybersecurity Platform
            </div>
          </motion.div>
          <motion.h1
            className="mx-auto max-w-4xl font-display text-4xl font-bold leading-tight md:text-6xl lg:text-7xl"
            initial="hidden" animate="visible" variants={fadeUp} custom={1}
          >
            Proactive cybersecurity for{" "}
            <span className="text-gradient">growth teams and regulated institutions</span>
          </motion.h1>
          <motion.p
            className="mx-auto mt-6 max-w-2xl text-lg text-muted-foreground md:text-xl"
            initial="hidden" animate="visible" variants={fadeUp} custom={2}
          >
            Prevention, continuous monitoring, and secure engineering practices - so you can ship with confidence.
          </motion.p>
          <motion.div className="mt-10 flex flex-col items-center gap-4 sm:flex-row sm:justify-center" initial="hidden" animate="visible" variants={fadeUp} custom={3}>
            <Link to="/contact">
              <Button size="lg" className="gap-2 text-base px-8">
                Request a Baseline Assessment
                <ArrowRight className="h-4 w-4" />
              </Button>
            </Link>
            <Link to="/pricing">
              <Button variant="outline" size="lg" className="text-base px-8">View Plans</Button>
            </Link>
          </motion.div>
        </div>
      </section>

      {/* What We Protect */}
      <section className="py-20 md:py-28">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="font-display text-3xl font-bold md:text-4xl">Coverage Domains</h2>
            <p className="mt-4 text-muted-foreground max-w-2xl mx-auto">Comprehensive protection across infrastructure, applications, and engineering workflows.</p>
          </div>
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
            {protectAreas.map((area, i) => (
              <motion.div
                key={area.title}
                className="glass-card rounded-xl p-6 hover:border-primary/30 transition-colors"
                initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUp} custom={i}
              >
                <div className="mb-4 inline-flex rounded-lg bg-primary/10 p-3">
                  <area.icon className="h-6 w-6 text-primary" />
                </div>
                <h3 className="font-display text-lg font-semibold mb-2">{area.title}</h3>
                <p className="text-sm text-muted-foreground">{area.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Social Proof */}
      <section className="py-16 md:py-20 bg-secondary/10">
        <div className="container mx-auto px-4">
          <div className="text-center mb-10">
            <p className="text-xs uppercase tracking-wide text-muted-foreground">Trusted by security-first teams</p>
            <h2 className="font-display text-2xl font-bold md:text-3xl mt-2">Proven for regulated and fast-scaling teams</h2>
          </div>
          <div className="grid gap-4 md:grid-cols-4 mb-8">
            {["Fintech", "Healthcare", "Education", "Public Sector"].map((label) => (
              <div key={label} className="glass-card rounded-xl p-4 text-center text-sm text-muted-foreground">
                {label}
              </div>
            ))}
          </div>
          <div className="grid gap-4 md:grid-cols-6">
            {clientLogos.map((logo) => (
              <div key={logo.name} className="glass-card rounded-xl p-3 flex items-center justify-center">
                <img src={logo.src} alt={`${logo.name} logo`} className="h-8 w-auto opacity-90" />
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Outcomes */}
      <section className="py-20 md:py-28">
        <div className="container mx-auto px-4">
          <div className="text-center mb-12">
            <h2 className="font-display text-3xl font-bold md:text-4xl">Outcomes That Matter</h2>
            <p className="mt-4 text-muted-foreground">Security improvements you can measure and report.</p>
          </div>
          <div className="grid gap-6 md:grid-cols-3 max-w-4xl mx-auto">
            {outcomes.map((item) => (
              <div key={item.label} className="glass-card rounded-xl p-6 text-center">
                <p className="font-display text-3xl font-semibold">{item.value}</p>
                <p className="mt-2 text-sm text-muted-foreground">{item.label}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Services Overview */}
      <section className="py-20 md:py-28 bg-secondary/20">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="font-display text-3xl font-bold md:text-4xl">Our Services</h2>
          </div>
          <div className="grid gap-8 md:grid-cols-2 max-w-4xl mx-auto">
            <div className="glass-card rounded-xl p-8">
              <div className="inline-flex rounded-lg bg-primary/10 p-3 mb-4">
                <Shield className="h-6 w-6 text-primary" />
              </div>
              <h3 className="font-display text-xl font-semibold mb-3">Core Protection</h3>
              <ul className="space-y-3 text-sm text-muted-foreground">
                {[
                  "Infrastructure + network exposure scanning (safe, non-intrusive)",
                  "Web security checks (headers, TLS, cookies, CORS)",
                  "Active validation probes (reflected input, common misconfig paths)",
                  "Baseline SAST for risky patterns (auth/debug/injection sinks)",
                  "Dependency and secrets scanning",
                  "Monthly security reports with prioritized remediation guidance",
                ].map((item) => (
                  <li key={item} className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-success mt-0.5 shrink-0" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
            <div className="glass-card rounded-xl p-8 border-primary/30 glow-primary">
              <div className="inline-flex rounded-lg bg-accent/10 p-3 mb-4">
                <Lock className="h-6 w-6 text-accent" />
              </div>
              <h3 className="font-display text-xl font-semibold mb-3">Advanced Protection</h3>
              <ul className="space-y-3 text-sm text-muted-foreground">
                {[
                  "Everything in Core Protection",
                  "Continuous monitoring and alerting for critical assets",
                  "Known-vulnerability correlation for common services (CVE-aware signatures)",
                  "Expanded web validation (XSS/SQL error leakage/traversal indicators)",
                  "Enhanced input validation + unsafe deserialization pattern detection in source",
                  "Cloud security posture management (AWS/Azure/GCP)",
                  "Compliance readiness (OWASP, ISO 27001, NIST)",
                  "Priority incident response + dedicated security advisor",
                ].map((item) => (
                  <li key={item} className="flex items-start gap-2">
                    <CheckCircle className="h-4 w-4 text-accent mt-0.5 shrink-0" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="py-20 md:py-28">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16">
            <h2 className="font-display text-3xl font-bold md:text-4xl">How It Works</h2>
            <p className="mt-4 text-muted-foreground">A streamlined process from onboarding to continuous protection.</p>
          </div>
          <div className="grid gap-8 md:grid-cols-2 lg:grid-cols-4 max-w-5xl mx-auto">
            {howItWorks.map((step, i) => (
              <motion.div
                key={step.step}
                className="text-center"
                initial="hidden" whileInView="visible" viewport={{ once: true }} variants={fadeUp} custom={i}
              >
                <div className="mx-auto mb-4 inline-flex h-14 w-14 items-center justify-center rounded-xl bg-secondary border border-border">
                  <step.icon className="h-6 w-6 text-primary" />
                </div>
                <div className="text-xs font-semibold text-primary mb-2">Step {step.step}</div>
                <h3 className="font-display font-semibold mb-2">{step.title}</h3>
                <p className="text-sm text-muted-foreground">{step.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Security Assurance */}
      <section className="py-20 md:py-28 bg-secondary/20">
        <div className="container mx-auto px-4">
          <div className="text-center mb-14">
            <h2 className="font-display text-3xl font-bold md:text-4xl">Security & Data Handling</h2>
            <p className="mt-4 text-muted-foreground max-w-2xl mx-auto">
              Built with consent-based scanning, least-privilege access, and audit-grade evidence collection.
            </p>
          </div>
          <div className="grid gap-6 md:grid-cols-3">
            {trustSignals.map((signal) => (
              <div key={signal.title} className="glass-card rounded-xl p-6">
                <h3 className="font-display font-semibold mb-2">{signal.title}</h3>
                <p className="text-sm text-muted-foreground">{signal.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Trust Signals */}
      <section className="py-20 md:py-28 bg-secondary/20">
        <div className="container mx-auto px-4 text-center">
          <h2 className="font-display text-3xl font-bold md:text-4xl mb-12">Built on Trust & Best Practices</h2>
          <div className="grid gap-6 md:grid-cols-3 max-w-3xl mx-auto">
            {[
              { title: "Secure Processes", desc: "Every engagement follows documented, repeatable security procedures." },
              { title: "Industry Standards", desc: "Aligned with OWASP, CWE/SANS Top 25, and secure coding guidelines." },
              { title: "Clear Reporting", desc: "Findings translated into business impact - not raw vulnerability dumps." },
            ].map((signal) => (
              <div key={signal.title} className="glass-card rounded-xl p-6">
                <h3 className="font-display font-semibold mb-2">{signal.title}</h3>
                <p className="text-sm text-muted-foreground">{signal.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* FAQs */}
      <section className="py-20 md:py-28">
        <div className="container mx-auto px-4">
          <div className="text-center mb-12">
            <h2 className="font-display text-3xl font-bold md:text-4xl">Frequently Asked Questions</h2>
            <p className="mt-4 text-muted-foreground">Answers to the questions security leaders ask most.</p>
          </div>
          <div className="grid gap-6 md:grid-cols-2">
            {faqs.map((item) => (
              <div key={item.q} className="glass-card rounded-xl p-6">
                <h3 className="font-display font-semibold mb-2">{item.q}</h3>
                <p className="text-sm text-muted-foreground">{item.a}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20 md:py-28">
        <div className="container mx-auto px-4 text-center">
          <div className="mx-auto max-w-2xl rounded-2xl bg-gradient-to-br from-primary/10 to-accent/10 border border-border p-12">
            <h2 className="font-display text-3xl font-bold mb-4">Ready to secure your stack?</h2>
            <p className="text-muted-foreground mb-8">Request a baseline assessment and see where you stand.</p>
            <Link to="/contact">
              <Button size="lg" className="gap-2 px-8">
                Request a Baseline Assessment
                <ArrowRight className="h-4 w-4" />
              </Button>
            </Link>
          </div>
        </div>
      </section>

      <Footer />
    </div>
  );
}
