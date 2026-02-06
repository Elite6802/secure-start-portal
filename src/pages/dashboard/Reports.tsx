import { reports } from "@/data/mockData";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { FileText, Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

export default function Reports() {
  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Security Reports</h1>
      <p className="text-sm text-muted-foreground mb-8">Comprehensive security assessments and findings.</p>

      <div className="space-y-4">
        {reports.map((report) => (
          <div key={report.id} className="glass-card rounded-xl p-6">
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-start gap-3">
                <div className="rounded-lg bg-primary/10 p-2 mt-0.5">
                  <FileText className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <h3 className="font-display font-semibold text-sm">{report.title}</h3>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-xs text-muted-foreground">{report.date}</span>
                    <Badge variant="outline" className="text-xs font-normal">{report.scope}</Badge>
                  </div>
                </div>
              </div>
              <Button variant="outline" size="sm" className="gap-1.5 text-xs">
                <Download className="h-3.5 w-3.5" />
                PDF
              </Button>
            </div>
            <p className="text-sm text-muted-foreground mb-3">{report.summary}</p>
            <div className="flex gap-2">
              <SeverityBadge level="High" count={report.severity.high} />
              <SeverityBadge level="Medium" count={report.severity.medium} />
              <SeverityBadge level="Low" count={report.severity.low} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
