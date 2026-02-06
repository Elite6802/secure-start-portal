import { assets } from "@/data/mockData";
import { SeverityBadge } from "@/components/dashboard/SeverityBadge";
import { StatusBadge } from "@/components/dashboard/StatusBadge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

export default function Assets() {
  return (
    <div>
      <h1 className="font-display text-2xl font-bold mb-1">Assets</h1>
      <p className="text-sm text-muted-foreground mb-8">All registered infrastructure, applications, and code repositories.</p>

      <div className="glass-card rounded-xl overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Asset ID</TableHead>
              <TableHead>Name</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Risk Level</TableHead>
              <TableHead>Last Scan</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {assets.map((asset) => (
              <TableRow key={asset.id}>
                <TableCell className="font-mono text-xs">{asset.id}</TableCell>
                <TableCell className="font-medium">{asset.name}</TableCell>
                <TableCell className="text-muted-foreground text-sm">{asset.type}</TableCell>
                <TableCell><StatusBadge status={asset.status} /></TableCell>
                <TableCell><SeverityBadge level={asset.risk} /></TableCell>
                <TableCell className="text-sm text-muted-foreground">{asset.lastScan}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
