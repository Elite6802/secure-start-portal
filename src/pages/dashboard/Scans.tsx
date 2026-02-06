import { scans } from "@/data/mockData";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export default function Scans() {
  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Security Scans</h1>
      <p className="text-sm text-muted-foreground mb-8">All security scans across your assets.</p>

      <div className="glass-card rounded-xl overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Scan ID</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Target</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Findings</TableHead>
              <TableHead>Started</TableHead>
              <TableHead>Completed</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {scans.map((scan) => (
              <TableRow key={scan.id}>
                <TableCell className="font-mono text-xs">{scan.id}</TableCell>
                <TableCell className="font-medium text-sm">{scan.type}</TableCell>
                <TableCell className="text-sm text-muted-foreground">{scan.target}</TableCell>
                <TableCell><StatusBadge status={scan.status} /></TableCell>
                <TableCell>
                  {scan.status === "Completed" ? (
                    <div className="flex gap-1.5">
                      <SeverityBadge level="High" count={scan.severity.high} />
                      <SeverityBadge level="Medium" count={scan.severity.medium} />
                      <SeverityBadge level="Low" count={scan.severity.low} />
                    </div>
                  ) : (
                    <span className="text-xs text-muted-foreground">—</span>
                  )}
                </TableCell>
                <TableCell className="text-sm text-muted-foreground">{scan.startedAt || "—"}</TableCell>
                <TableCell className="text-sm text-muted-foreground">{scan.completedAt || "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
