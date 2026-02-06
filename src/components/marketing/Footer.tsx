import { Shield } from "lucide-react";
import { Link } from "react-router-dom";

export function Footer() {
  return (
    <footer className="border-t border-border bg-secondary/30">
      <div className="container mx-auto px-4 py-12">
        <div className="grid gap-8 md:grid-cols-4">
          <div>
            <div className="flex items-center gap-2 mb-4">
              <Shield className="h-6 w-6 text-primary" />
              <span className="font-display text-lg font-bold">Aegis</span>
            </div>
            <p className="text-sm text-muted-foreground">
              Proactive cybersecurity for startups and institutions. Prevention, monitoring, and secure development.
            </p>
          </div>
          <div>
            <h4 className="font-display font-semibold mb-3 text-sm">Services</h4>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li>Infrastructure Security</li>
              <li>Web & API Security</li>
              <li>Code Security</li>
              <li>Cloud Security</li>
            </ul>
          </div>
          <div>
            <h4 className="font-display font-semibold mb-3 text-sm">Company</h4>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li><Link to="/pricing" className="hover:text-primary transition-colors">Pricing</Link></li>
              <li><Link to="/contact" className="hover:text-primary transition-colors">Contact</Link></li>
              <li><Link to="/login" className="hover:text-primary transition-colors">Client Portal</Link></li>
            </ul>
          </div>
          <div>
            <h4 className="font-display font-semibold mb-3 text-sm">Standards</h4>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li>OWASP Top 10</li>
              <li>CWE/SANS Top 25</li>
              <li>Secure Coding Guidelines</li>
              <li>PCI DSS Compliance</li>
            </ul>
          </div>
        </div>
        <div className="mt-10 border-t border-border pt-6 text-center text-xs text-muted-foreground">
          © 2026 Aegis Security. All rights reserved.
        </div>
      </div>
    </footer>
  );
}
