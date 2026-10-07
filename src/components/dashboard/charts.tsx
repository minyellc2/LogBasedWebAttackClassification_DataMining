"use client";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  PieChart, Pie, Cell, Legend,
} from "recharts";

const ATTACK_COLORS = [
  "#dc2626", "#ea580c", "#d97706", "#65a30d", "#0891b2",
  "#0284c7", "#7c3aed", "#c026d3", "#db2777", "#475569",
];

interface ChartsProps {
  byAttackType: { label: string; count: number }[];
  byMethod: { method: string; count: number; attacks: number }[];
  byStatus: { status: number; count: number; attacks: number }[];
}

export function Charts({ byAttackType, byMethod, byStatus }: ChartsProps) {
  const attackData = byAttackType.filter((d) => d.label !== "benign");
  const methodData = byMethod;
  const statusData = byStatus;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {/* Attack type distribution */}
      <Card className="shadow-sm">
        <CardHeader>
          <CardTitle className="text-base">Attack Type Distribution</CardTitle>
          <CardDescription>Detection count by attack family</CardDescription>
        </CardHeader>
        <CardContent>
          {attackData.length === 0 ? (
            <div className="h-[280px] flex items-center justify-center text-muted-foreground text-sm">
              No attacks detected
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={attackData} layout="vertical" margin={{ left: 20, right: 20, top: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 12 }} />
                <YAxis dataKey="label" type="category" width={140} tick={{ fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ fontSize: 12, borderRadius: 8 }}
                  formatter={(v: number) => [v, "Detections"]}
                />
                <Bar dataKey="count" fill="#dc2626" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </CardContent>
      </Card>

      {/* HTTP method split */}
      <Card className="shadow-sm">
        <CardHeader>
          <CardTitle className="text-base">HTTP Method Breakdown</CardTitle>
          <CardDescription>Benign vs attack per HTTP verb</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={methodData} margin={{ left: 0, right: 20, top: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="method" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} />
              <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8 }} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Bar dataKey="count" name="Benign" stackId="a" fill="#10b981" radius={[0, 0, 0, 0]} />
              <Bar dataKey="attacks" name="Attacks" stackId="a" fill="#dc2626" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Status code distribution (pie) */}
      <Card className="shadow-sm">
        <CardHeader>
          <CardTitle className="text-base">HTTP Status Codes</CardTitle>
          <CardDescription>Response code share</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie
                data={statusData}
                dataKey="count"
                nameKey="status"
                cx="50%" cy="50%"
                outerRadius={90}
                label={(entry) => `${entry.status}`}
                labelLine={false}
              >
                {statusData.map((_, i) => (
                  <Cell key={i} fill={ATTACK_COLORS[i % ATTACK_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ fontSize: 12, borderRadius: 8 }}
                formatter={(v: number, n: string) => [v, `HTTP ${n}`]}
              />
              <Legend wrapperStyle={{ fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Top attackers */}
      <Card className="shadow-sm">
        <CardHeader>
          <CardTitle className="text-base">Status Code: Benign vs Attack</CardTitle>
          <CardDescription>Where attacks land in the response spectrum</CardDescription>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={statusData} margin={{ left: 0, right: 20, top: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="status" tick={{ fontSize: 12 }} />
              <YAxis tick={{ fontSize: 12 }} />
              <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8 }} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Bar dataKey="count" name="Benign" stackId="a" fill="#10b981" />
              <Bar dataKey="attacks" name="Attacks" stackId="a" fill="#dc2626" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  );
}
