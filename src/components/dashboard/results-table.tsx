"use client";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ShieldAlert } from "lucide-react";
import type { ClassificationResult } from "@/lib/engine/classifier";

interface ResultsTableProps {
  results: ClassificationResult[];
  showOnlyAttacks?: boolean;
  maxRows?: number;
}

const SEVERITY_COLOR: Record<string, string> = {
  sql_injection_attempt: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  cross_site_scripting: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  path_traversal: "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300",
  rce_read_file: "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300",
  remote_code: "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300",
  rce_shell: "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300",
  rce_java: "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300",
  rce_sysinfo: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300",
  dir_scan: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  dir_scan_go: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  dir_scan_python: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  api_call: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  benign: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
};

export function ResultsTable({ results, showOnlyAttacks = false, maxRows = 200 }: ResultsTableProps) {
  const filtered = showOnlyAttacks
    ? results.filter((r) => r.label.is_attack === 1)
    : results;
  const rows = filtered.slice(0, maxRows);

  return (
    <Card className="shadow-sm">
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-2">
          <ShieldAlert className="h-4 w-4 text-red-600" />
          {showOnlyAttacks ? "Flagged Attacks" : "Classified Entries"}
        </CardTitle>
        <CardDescription>
          Showing {rows.length} of {filtered.length} {showOnlyAttacks ? "attacks" : "entries"}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[420px] rounded-md border">
          <Table>
            <TableHeader className="sticky top-0 bg-background z-10">
              <TableRow>
                <TableHead className="w-[140px]">IP</TableHead>
                <TableHead className="w-[60px]">Method</TableHead>
                <TableHead>URL</TableHead>
                <TableHead className="w-[60px]">Status</TableHead>
                <TableHead className="w-[170px]">Label</TableHead>
                <TableHead className="w-[160px]">Matched Rule</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                    No {showOnlyAttacks ? "attacks" : "entries"} to display
                  </TableCell>
                </TableRow>
              ) : (
                rows.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-mono text-xs">{r.parsed.ip}</TableCell>
                    <TableCell className="font-mono text-xs">{r.parsed.method}</TableCell>
                    <TableCell className="font-mono text-xs max-w-[280px] truncate" title={r.parsed.url}>
                      {r.parsed.url}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{r.parsed.status}</TableCell>
                    <TableCell>
                      <Badge
                        variant="secondary"
                        className={`text-[10px] font-mono ${SEVERITY_COLOR[r.label.label] || ""}`}
                      >
                        {r.label.label}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-[10px] text-muted-foreground">
                      {r.label.matched_rule || "—"}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
