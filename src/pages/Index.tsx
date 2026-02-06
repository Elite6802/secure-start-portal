import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Shield, Server, Globe, Cloud, Code, ArrowRight, CheckCircle, ClipboardCheck, BarChart3, FileSearch, ShieldCheck, Lock, Eye } from "lucide-react";
import { Button } from "@/components/ui/button";
import { MarketingNav } from "@/components/marketing/MarketingNav";
import { Footer } from "@/components/marketing/Footer";

const fadeUp = {
  hidden: { opacity: 0, y: 20 },
  visible: (i: number) => ({ opacity: 1, y: 0, transition: { delay: i * 0.1, duration: 0.5 } }),
};

const protectAreas = [
  { icon: Server, title: "Infrastructure & Networks", desc: "Continuous monitoring of servers, firewalls, and network configurations." },
  { icon: Globe, title: "Web & APIs", desc: "Vulnerability assessments for web applications and API endpoints." },
  { icon: Cloud, title: "Cloud Environments", desc: "Security posture management across AWS, Azure, and GCP." },
  { icon: Code, title: "Code & Software", desc: "Static analysis, dependency scanning, and secure coding enforcement." },
];

const howItWorks = [
  { step: "01", icon: ClipboardCheck, title: "Asset Onboarding", desc: "Register your infrastructure, applications, and code repositories." },
  { step: "02", icon: FileSearch, title: "Automated Scans", desc: "Continuous security scanning across all registered assets." },
  { step: "03", icon: Eye, title: "Reviews & Compliance", desc: "Code reviews, compliance checks, and standards validation." },
  { step: "04", icon: BarChart3, title: "Reporting & Guidance", desc: "Clear reports with prioritized remediation steps." },
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
              Cybersecurity-as-a-Service
            </div>
          </motion.div>
          <motion.h1
            className="mx-auto max-w-4xl font-display text-4xl font-bold leading-tight md:text-6xl lg:text-7xl"
            initial="hidden" animate="visible" variants={fadeUp} custom={1}
          >
            Proactive cybersecurity for{" "}
            <span className="text-gradient">startups & institutions</span>
          </motion.h1>
          <motion.p
            className="mx-auto mt-6 max-w-2xl text-lg text-muted-foreground md:text-xl"
            initial="hidden" animate="visible" variants={fadeUp} custom={2}
          >
            Prevention, continuous monitoring, and developer-friendly security practices — so you can build with confidence.
          </motion.p>
          <motion.div className="mt-10 flex flex-col items-center gap-4 sm:flex-row sm:justify-center" initial="hidden" animate="visible" variants={fadeUp} custom={3}>
            <Link to="/contact">
              <Button size="lg" className="gap-2 text-base px-8">
                Request a Free Security Check
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
            <h2 className="font-display text-3xl font-bold md:text-4xl">What We Protect</h2>
            <p className="mt-4 text-muted-foreground max-w-2xl mx-auto">Comprehensive security coverage across your entire technology stack.</p>
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
                {["Infrastructure vulnerability scanning", "Web application security testing", "Basic code security analysis", "Monthly security reports", "Email support & guidance"].map((item) => (
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
                {["Everything in Core Protection", "Continuous monitoring & alerting", "Advanced SAST & dependency scanning", "Cloud security posture management", "Compliance readiness (OWASP, PCI DSS)", "Priority incident response", "Dedicated security advisor"].map((item) => (
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

      {/* Trust Signals */}
      <section className="py-20 md:py-28 bg-secondary/20">
        <div className="container mx-auto px-4 text-center">
          <h2 className="font-display text-3xl font-bold md:text-4xl mb-12">Built on Trust & Best Practices</h2>
          <div className="grid gap-6 md:grid-cols-3 max-w-3xl mx-auto">
            {[
              { title: "Secure Processes", desc: "Every engagement follows documented, repeatable security procedures." },
              { title: "Industry Standards", desc: "Aligned with OWASP, CWE/SANS Top 25, and secure coding guidelines." },
              { title: "Clear Reporting", desc: "Findings translated into business impact — not raw vulnerability dumps." },
            ].map((signal) => (
              <div key={signal.title} className="glass-card rounded-xl p-6">
                <h3 className="font-display font-semibold mb-2">{signal.title}</h3>
                <p className="text-sm text-muted-foreground">{signal.desc}</p>
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
            <p className="text-muted-foreground mb-8">Get a free baseline security assessment and see where you stand.</p>
            <Link to="/contact">
              <Button size="lg" className="gap-2 px-8">
                Request a Free Security Check
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
