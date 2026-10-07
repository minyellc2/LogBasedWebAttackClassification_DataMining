"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle, ShieldCheck, FileText, Activity } from "lucide-react";

interface KpiCardsProps {
  total: number;
  attacks: number;
  benign: number;
  attackRatio: number;
  unparseable: number;
  /** When provided, the "Total Entries" hint shows "X of Y input lines parsed" */
  totalInputLines?: number | null;
}

export function KpiCards({ total, attacks, benign, attackRatio, unparseable, totalInputLines }: KpiCardsProps) {
  const pct = (attackRatio * 100).toFixed(2);
  const parsedHint = totalInputLines && totalInputLines > total
    ? `${total.toLocaleString()} of ${totalInputLines.toLocaleString()} input lines parsed`
    : "Parsed log lines";

  const cards = [
    {
      title: "Total Entries",
      value: total.toLocaleString(),
      icon: FileText,
      hint: parsedHint,
      tone: "text-foreground",
    },
    {
      title: "Attacks Detected",
      value: attacks.toLocaleString(),
      icon: AlertTriangle,
      hint: `${pct}% of parsed`,
      tone: "text-red-600 dark:text-red-400",
    },
    {
      title: "Benign Traffic",
      value: benign.toLocaleString(),
      icon: ShieldCheck,
      hint: `${(100 - parseFloat(pct)).toFixed(2)}% of parsed`,
      tone: "text-emerald-600 dark:text-emerald-400",
    },
    {
      title: "Unparseable",
      value: unparseable.toLocaleString(),
      icon: Activity,
      hint: totalInputLines
        ? `${unparseable.toLocaleString()} of ${totalInputLines.toLocaleString()} input lines`
        : "Malformed lines skipped",
      tone: "text-amber-600 dark:text-amber-400",
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((c) => (
        <Card key={c.title} className="shadow-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2 space-y-0">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              {c.title}
            </CardTitle>
            <c.icon className={`h-4 w-4 ${c.tone}`} />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{c.value}</div>
            <p className="text-xs text-muted-foreground mt-1">{c.hint}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
