"use client";

import { useState, useEffect, useCallback } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import {
  Activity, Upload, BarChart3, Database, ShieldAlert, Play,
  Trash2, FileWarning, Terminal, BookOpen,
} from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  Legend, LineChart, Line, ComposedChart, ReferenceLine, Cell,
} from "recharts";
import {
  type ClassificationResult, type ClassificationSummary,
  MODEL_METRICS, CROSS_VALIDATION, PER_CLASS_METRICS,
  FEATURE_IMPORTANCES, ATTACK_TAXONOMY, SAMPLE_LOG_LINES,
  KMEANS_METRICS, KMEANS_BEST_K, KMEANS_BEST_SILHOUETTE,
} from "@/lib/engine/classifier";
import { KpiCards } from "@/components/dashboard/kpi-cards";
import { Charts } from "@/components/dashboard/charts";
import { ResultsTable } from "@/components/dashboard/results-table";

const SEVERITY_BADGE: Record<string, string> = {
  Critical: "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300",
  High: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  Medium: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
};

const SAMPLE_TO_PASTE = [
  '45.133.1.99 - - [07/Oct/2025:23:59:00 +0700] "GET /login.php?u=admin&p=%27+OR+%271%27%3D%271 HTTP/1.0" 200 2500 "-" "sqlmap/1.7.2"',
  '45.133.1.98 - - [07/Oct/2025:23:59:01 +0700] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.0" 200 1800 "-" "Mozilla/5.0"',
  '203.0.113.42 - - [07/Oct/2025:23:59:02 +0700] "GET /blog/post-7 HTTP/1.0" 200 3400 "-" "Mozilla/5.0 (Windows NT 10.0)"',
  '45.133.1.97 - - [07/Oct/2025:23:59:03 +0700] "GET /admin HTTP/1.0" 404 650 "-" "Go-http-client/1.1"',
  '45.133.1.96 - - [07/Oct/2025:23:59:04 +0700] "GET /shell.php?cmd=id HTTP/1.0" 200 800 "-" "Mozilla/5.0"',
].join("\n");

export default function Home() {
  const [activeTab, setActiveTab] = useState("dashboard");

  // Sample dataset state (always loaded on mount; used as the default Dashboard view)
  const [sampleSummary, setSampleSummary] = useState<ClassificationSummary | null>(null);
  const [sampleResults, setSampleResults] = useState<ClassificationResult[]>([]);
  const [sampleLoading, setSampleLoading] = useState(true);

  // Classify tab state
  const [inputText, setInputText] = useState("");
  const [classifyLoading, setClassifyLoading] = useState(false);
  const [classifySummary, setClassifySummary] = useState<ClassificationSummary | null>(null);
  const [classifyResults, setClassifyResults] = useState<ClassificationResult[]>([]);
  const [classifyUnparseable, setClassifyUnparseable] = useState<{ line: string; index: number }[]>([]);
  const [truncated, setTruncated] = useState(false);
  const [totalInputLines, setTotalInputLines] = useState<number | null>(null);

  // What the Dashboard is currently showing: "sample" by default, switches to "uploaded"
  // after the user runs the classifier. Reset via the "Show sample dataset" button.
  const [dataSource, setDataSource] = useState<"sample" | "uploaded">("sample");

  // Load sample dataset on mount
  const loadSample = useCallback(async () => {
    setSampleLoading(true);
    try {
      const res = await fetch("/api/sample");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setSampleSummary(data.summary);
      setSampleResults(data.results);
    } catch (e) {
      toast.error(`Failed to load sample: ${(e as Error).message}`);
    } finally {
      setSampleLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSample();
  }, [loadSample]);

  // Run classifier on input text
  const handleClassify = async () => {
    if (!inputText.trim()) {
      toast.error("Please paste some log lines first.");
      return;
    }
    setClassifyLoading(true);
    try {
      const res = await fetch("/api/classify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: inputText }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setClassifySummary(data.summary);
      setClassifyResults(data.results);
      setClassifyUnparseable(data.unparseable || []);
      setTruncated(!!data.truncated);
      setTotalInputLines(data.totalInputLines ?? null);
      // Flip the Dashboard to show the user's data instead of the sample
      setDataSource("uploaded");
      toast.success(
        `Classified ${data.summary.total.toLocaleString()} entries — ${data.summary.attacks.toLocaleString()} attacks detected`
      );
      if (data.truncated) {
        toast.warning(`Input truncated to ${data.maxLines.toLocaleString()} lines.`);
      }
    } catch (e) {
      toast.error(`Classification failed: ${(e as Error).message}`);
    } finally {
      setClassifyLoading(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    // No client-side truncation — the API enforces the line cap (10,000 lines).
    // We only cap at 5 MB to protect against pathological inputs.
    const MAX_INPUT_BYTES = 5 * 1024 * 1024;
    const trimmed = text.length > MAX_INPUT_BYTES ? text.slice(0, MAX_INPUT_BYTES) : text;
    setInputText(trimmed);
    const lineCount = trimmed.split(/\r?\n/).filter((l) => l.trim()).length;
    toast.info(
      `Loaded ${file.name} (${(file.size / 1024).toFixed(1)} KB, ${lineCount.toLocaleString()} non-empty lines)`
    );
  };

  return (
    <div className="min-h-screen flex flex-col bg-muted/30">
      {/* Header */}
      <header className="border-b bg-background sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-lg bg-red-600 flex items-center justify-center text-white">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-base sm:text-lg font-bold leading-tight">
                Log-Based Web Attack Classifier
              </h1>
              <p className="text-[11px] text-muted-foreground leading-tight">
                IS-212 Data &amp; Knowledge Mining — Interactive Demo
              </p>
            </div>
          </div>
          <Badge variant="outline" className="hidden sm:inline-flex text-[11px]">
            <Terminal className="h-3 w-3 mr-1" />
            Apache combined log format
          </Badge>
        </div>
      </header>

      {/* Main content */}
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-2 sm:grid-cols-4 h-auto">
            <TabsTrigger value="dashboard" className="flex items-center gap-2 py-2">
              <Activity className="h-4 w-4" /> Dashboard
            </TabsTrigger>
            <TabsTrigger value="classify" className="flex items-center gap-2 py-2">
              <Upload className="h-4 w-4" /> Classify
            </TabsTrigger>
            <TabsTrigger value="explore" className="flex items-center gap-2 py-2">
              <Database className="h-4 w-4" /> Explore
            </TabsTrigger>
            <TabsTrigger value="model" className="flex items-center gap-2 py-2">
              <BarChart3 className="h-4 w-4" /> Model
            </TabsTrigger>
          </TabsList>

          {/* ============ Dashboard ============ */}
          <TabsContent value="dashboard" className="space-y-6">
            {(() => {
              // Unified view: show uploaded data if available, otherwise the sample
              const usingUploaded = dataSource === "uploaded" && classifySummary;
              const summary = usingUploaded ? classifySummary! : sampleSummary;
              const results = usingUploaded ? classifyResults : sampleResults;
              const loading = !usingUploaded && sampleLoading;

              if (loading || !summary) return <DashboardSkeleton />;

              return (
                <>
                  {/* Source banner — makes it obvious which dataset is on screen */}
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <h2 className="text-lg font-semibold mb-1 flex items-center gap-2">
                        {usingUploaded ? "Your Uploaded Logs" : "Sample Dataset Overview"}
                        <Badge variant={usingUploaded ? "default" : "secondary"} className="text-[10px]">
                          {usingUploaded ? "YOUR DATA" : "SAMPLE"}
                        </Badge>
                      </h2>
                      <p className="text-sm text-muted-foreground">
                        {usingUploaded
                          ? `Showing results from your last classification run (${summary.total.toLocaleString()} parsed entries${totalInputLines && totalInputLines > summary.total ? ` of ${totalInputLines.toLocaleString()} input lines` : ""}).`
                          : `A representative sample of ${SAMPLE_LOG_LINES.length} Apache access log lines (mix of benign traffic and 9 attack families) is preloaded.`}{" "}
                        Use the <strong>Classify</strong> tab to analyse your own logs.
                      </p>
                    </div>
                    {usingUploaded && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setDataSource("sample")}
                      >
                        Show sample dataset
                      </Button>
                    )}
                  </div>

                  <KpiCards
                    total={summary.total}
                    attacks={summary.attacks}
                    benign={summary.benign}
                    attackRatio={summary.attackRatio}
                    unparseable={summary.unparseable}
                    totalInputLines={usingUploaded ? totalInputLines : null}
                  />
                  <Charts
                    byAttackType={summary.byAttackType}
                    byMethod={summary.byMethod}
                    byStatus={summary.byStatus}
                  />
                  <ResultsTable results={results} showOnlyAttacks maxRows={100} />
                  {summary.topAttackers.length > 0 && (
                    <Card className="shadow-sm">
                      <CardHeader>
                        <CardTitle className="text-base">Top Attacker IPs</CardTitle>
                        <CardDescription>Source IPs ranked by attack count</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="max-h-72 overflow-auto rounded-md border">
                          <Table className="table-fixed w-full">
                            <TableHeader className="sticky top-0 bg-background z-10">
                              <TableRow>
                                <TableHead className="w-[25%]">IP</TableHead>
                                <TableHead className="w-[15%]">Attacks</TableHead>
                                <TableHead className="w-[60%]">Attack Families</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {summary.topAttackers.map((a) => (
                                <TableRow key={a.ip}>
                                  <TableCell className="font-mono text-xs break-all align-top">
                                    {a.ip}
                                  </TableCell>
                                  <TableCell className="font-mono align-top">{a.count}</TableCell>
                                  <TableCell className="align-top">
                                    <div className="flex flex-wrap gap-1">
                                      {a.labels.map((l) => (
                                        <Badge key={l} variant="outline" className="text-[10px] font-mono break-all">
                                          {l}
                                        </Badge>
                                      ))}
                                    </div>
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </div>
                      </CardContent>
                    </Card>
                  )}
                </>
              );
            })()}
          </TabsContent>

          {/* ============ Classify ============ */}
          <TabsContent value="classify" className="space-y-6">
            <div>
              <h2 className="text-lg font-semibold mb-1">Upload or Paste Logs</h2>
              <p className="text-sm text-muted-foreground">
                Paste Apache combined-format access log lines below, or upload a <code>.log</code> / <code>.txt</code> file. The classifier will parse, label, and aggregate the results in real time.
              </p>
            </div>

            <Card className="shadow-sm">
              <CardHeader>
                <CardTitle className="text-base">Input</CardTitle>
                <CardDescription>One log line per row — up to 10,000 lines per request, up to 5 MB file size</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <Textarea
                  value={inputText}
                  onChange={(e) => setInputText(e.target.value)}
                  placeholder={SAMPLE_TO_PASTE}
                  className="font-mono text-xs min-h-[200px] max-h-[420px]"
                />
                <div className="flex flex-wrap gap-2">
                  <Button onClick={handleClassify} disabled={classifyLoading}>
                    {classifyLoading ? (
                      <><Activity className="h-4 w-4 animate-pulse" /> Running…</>
                    ) : (
                      <><Play className="h-4 w-4" /> Run Classifier</>
                    )}
                  </Button>
                  <Button variant="outline" onClick={() => setInputText(SAMPLE_TO_PASTE)}>
                    Load Example
                  </Button>
                  <Button variant="outline" asChild>
                    <label className="cursor-pointer">
                      <Upload className="h-4 w-4 mr-2" /> Upload File
                      <input type="file" accept=".log,.txt,.csv" onChange={handleFileUpload} className="hidden" />
                    </label>
                  </Button>
                  <Button variant="ghost" onClick={() => { setInputText(""); setClassifyResults([]); setClassifySummary(null); setClassifyUnparseable([]); setTruncated(false); setTotalInputLines(null); setDataSource("sample"); }}>
                    <Trash2 className="h-4 w-4 mr-2" /> Clear
                  </Button>
                </div>
              </CardContent>
            </Card>

            {truncated && (
              <Card className="border-amber-400 bg-amber-50 dark:bg-amber-950/30">
                <CardContent className="py-3 flex items-center gap-2 text-sm text-amber-800 dark:text-amber-300">
                  <FileWarning className="h-4 w-4" />
                  Input was truncated to 10,000 lines for performance. {totalInputLines ? `Your file had ${totalInputLines.toLocaleString()} non-empty lines.` : ""}
                </CardContent>
              </Card>
            )}

            {classifySummary && classifySummary.unparseable > 0 && (
              <Card className="border-amber-400 bg-amber-50 dark:bg-amber-950/30">
                <CardContent className="py-3 flex items-center gap-2 text-sm text-amber-800 dark:text-amber-300">
                  <FileWarning className="h-4 w-4" />
                  <span>
                    <strong>{classifySummary.unparseable.toLocaleString()}</strong> of{" "}
                    {totalInputLines ? totalInputLines.toLocaleString() : classifySummary.total.toLocaleString()} input lines
                    could not be parsed (they don&rsquo;t match the Apache combined log format). See the unparseable list below.
                  </span>
                </CardContent>
              </Card>
            )}

            {classifySummary && (
              <>
                <KpiCards
                  total={classifySummary.total}
                  attacks={classifySummary.attacks}
                  benign={classifySummary.benign}
                  attackRatio={classifySummary.attackRatio}
                  unparseable={classifySummary.unparseable}
                  totalInputLines={totalInputLines}
                />
                <Charts
                  byAttackType={classifySummary.byAttackType}
                  byMethod={classifySummary.byMethod}
                  byStatus={classifySummary.byStatus}
                />
                <ResultsTable results={classifyResults} showOnlyAttacks={false} maxRows={200} />
              </>
            )}

            {classifyUnparseable.length > 0 && (
              <Card className="shadow-sm border-amber-300">
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2 text-amber-700 dark:text-amber-400">
                    <FileWarning className="h-4 w-4" />
                    Unparseable Lines ({classifyUnparseable.length})
                  </CardTitle>
                  <CardDescription>These lines did not match the Apache combined log regex and were skipped.</CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="max-h-48 rounded-md border">
                    <div className="p-3 space-y-1">
                      {classifyUnparseable.map((u, i) => (
                        <div key={i} className="font-mono text-xs text-muted-foreground">
                          <span className="text-amber-600">L{u.index + 1}:</span> {u.line.slice(0, 200)}
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* ============ Explore ============ */}
          <TabsContent value="explore" className="space-y-6">
            {(() => {
              const usingUploaded = dataSource === "uploaded" && classifySummary;
              const results = usingUploaded ? classifyResults : sampleResults;
              const loading = !usingUploaded && sampleLoading;
              return (
                <>
                  <div>
                    <h2 className="text-lg font-semibold mb-1 flex items-center gap-2">
                      Explore {usingUploaded ? "Your Uploaded Logs" : "Sample Dataset"}
                      <Badge variant={usingUploaded ? "default" : "secondary"} className="text-[10px]">
                        {usingUploaded ? "YOUR DATA" : "SAMPLE"}
                      </Badge>
                    </h2>
                    <p className="text-sm text-muted-foreground">
                      Browse all {results.length.toLocaleString()} classified entries{usingUploaded ? " from your last classification run" : " from the built-in sample"}. Filter by attack family or HTTP method.
                    </p>
                  </div>
                  <ExplorePanel results={results} loading={loading} />
                </>
              );
            })()}
          </TabsContent>

          {/* ============ Model Insights ============ */}
          <TabsContent value="model" className="space-y-6">
            <div>
              <h2 className="text-lg font-semibold mb-1">Model Insights</h2>
              <p className="text-sm text-muted-foreground">
                Evaluation results reproduced from the IS-212 project notebook (5,000-row working sample, 80/20 stratified split, 5-fold CV).
              </p>
            </div>

            {/* K-Means Best-K selection (descriptive mining) */}
            <Card className="shadow-sm">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Activity className="h-4 w-4" />
                  K-Means Clustering — Best K Selection
                </CardTitle>
                <CardDescription className="space-y-1">
                  <span>Descriptive mining on the 5,000-row sample (StandardScaler + KMeans, n_init=10, random_state=42).</span>
                  <span className="block text-xs text-muted-foreground">
                    Best <strong>k = {KMEANS_BEST_K}</strong> — silhouette coefficient peaks at <strong>{KMEANS_BEST_SILHOUETTE.toFixed(3)}</strong>, confirming the binary benign-vs-attack structure of the feature space.
                  </span>
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Dual-axis chart: inertia (elbow) on left, silhouette on right */}
                <ResponsiveContainer width="100%" height={340}>
                  <ComposedChart data={KMEANS_METRICS} margin={{ left: 0, right: 10, top: 10, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" vertical={false} />
                    <XAxis
                      dataKey="k"
                      tick={{ fontSize: 12 }}
                      label={{ value: "k (number of clusters)", position: "insideBottom", offset: -2, fontSize: 11, fill: "#666" }}
                    />
                    <YAxis
                      yAxisId="left"
                      tick={{ fontSize: 11 }}
                      label={{ value: "Inertia (within-cluster SS)", angle: -90, position: "insideLeft", fontSize: 11, fill: "#666", dy: 50 }}
                    />
                    <YAxis
                      yAxisId="right"
                      orientation="right"
                      domain={[0, 1]}
                      tick={{ fontSize: 11 }}
                      label={{ value: "Silhouette coefficient", angle: 90, position: "insideRight", fontSize: 11, fill: "#666", dy: 50 }}
                    />
                    <Tooltip
                      contentStyle={{ fontSize: 12, borderRadius: 8 }}
                      formatter={(v: number, name: string) => {
                        if (name === "Inertia (elbow)") return [v.toLocaleString(), name];
                        return [v.toFixed(4), name];
                      }}
                      labelFormatter={(label) => `k = ${label}`}
                    />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    {/* Vertical reference line at best k */}
                    <ReferenceLine
                      x={KMEANS_BEST_K}
                      stroke="#dc2626"
                      strokeDasharray="6 4"
                      strokeWidth={1.5}
                      yAxisId="right"
                      label={{
                        value: `Best k = ${KMEANS_BEST_K}`,
                        position: "top",
                        fill: "#dc2626",
                        fontSize: 11,
                        fontWeight: "bold",
                      }}
                    />
                    <Bar
                      yAxisId="left"
                      dataKey="inertia"
                      name="Inertia (elbow)"
                      fill="#0891b2"
                      radius={[4, 4, 0, 0]}
                      barSize={28}
                    />
                    <Line
                      yAxisId="right"
                      type="monotone"
                      dataKey="silhouette"
                      name="Silhouette"
                      stroke="#dc2626"
                      strokeWidth={2.5}
                      dot={{ r: 4, fill: "#dc2626" }}
                      activeDot={{ r: 6 }}
                    />
                  </ComposedChart>
                </ResponsiveContainer>

                {/* Interpretation note + per-k table */}
                <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
                  <div className="lg:col-span-2 text-xs text-muted-foreground space-y-2 bg-muted/40 border rounded-md p-3">
                    <p className="font-medium text-foreground text-sm">How to read this chart</p>
                    <p>
                      <strong>Blue bars (left axis):</strong> Inertia = within-cluster sum of squares. The elbow method looks for the &ldquo;elbow&rdquo; where additional clusters yield diminishing returns.
                    </p>
                    <p>
                      <strong>Red line (right axis):</strong> Silhouette coefficient in [−1, +1]. Higher = better cluster separation. The peak selects the best k (Rousseeuw, 1987).
                    </p>
                    <p>
                      <strong>Why k = {KMEANS_BEST_K}:</strong> silhouette peaks at {KMEANS_BEST_SILHOUETTE.toFixed(3)} — well above the local maxima at k = 7 (0.424) and k = 9 (0.436). This matches the binary benign-vs-attack structure of the labels.
                    </p>
                    <p className="text-[10px] italic">
                      Note: K-Means alone is not a reliable attack detector (silhouette 0.575 indicates separation but not precision). The supervised classifiers in the cards below are the main contribution.
                    </p>
                  </div>

                  <div className="lg:col-span-3">
                    <div className="max-h-72 overflow-auto rounded-md border">
                      <Table className="table-fixed w-full">
                        <TableHeader className="sticky top-0 bg-background z-10">
                          <TableRow>
                            <TableHead className="w-[15%]">k</TableHead>
                            <TableHead className="w-[42%]">Inertia</TableHead>
                            <TableHead className="w-[28%]">Silhouette</TableHead>
                            <TableHead className="w-[15%]">Rank</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {KMEANS_METRICS.map((m) => {
                            const rank = [...KMEANS_METRICS]
                              .sort((a, b) => b.silhouette - a.silhouette)
                              .findIndex((x) => x.k === m.k) + 1;
                            return (
                              <TableRow
                                key={m.k}
                                className={m.isBest ? "bg-red-50 dark:bg-red-950/30" : ""}
                              >
                                <TableCell className="font-mono text-xs font-bold">
                                  {m.isBest && <span className="text-red-600 mr-1">★</span>}
                                  {m.k}
                                </TableCell>
                                <TableCell className="font-mono text-xs">{m.inertia.toLocaleString()}</TableCell>
                                <TableCell className="font-mono text-xs">
                                  <span className={m.isBest ? "text-red-600 font-bold" : ""}>
                                    {m.silhouette.toFixed(3)}
                                  </span>
                                </TableCell>
                                <TableCell>
                                  <Badge
                                    variant={rank === 1 ? "default" : "outline"}
                                    className={`text-[10px] ${rank === 1 ? "bg-red-600 text-white" : ""}`}
                                  >
                                    #{rank}
                                  </Badge>
                                </TableCell>
                              </TableRow>
                            );
                          })}
                        </TableBody>
                      </Table>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Binary metrics table + Metric comparison chart (side by side on large screens) */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <Card className="shadow-sm">
                <CardHeader>
                  <CardTitle className="text-base">Binary Classification Results</CardTitle>
                  <CardDescription>Hold-out test set (1,000 rows; 212 attacks)</CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="max-h-72 rounded-md border">
                    <Table>
                      <TableHeader className="sticky top-0 bg-background">
                        <TableRow>
                          <TableHead>Model</TableHead>
                          <TableHead>Acc.</TableHead>
                          <TableHead>Bal.Acc.</TableHead>
                          <TableHead>Prec.</TableHead>
                          <TableHead>Rec.</TableHead>
                          <TableHead>F1</TableHead>
                          <TableHead>AUC</TableHead>
                          <TableHead>MCC</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {MODEL_METRICS.map((m) => (
                          <TableRow key={m.model}>
                            <TableCell className="font-medium text-xs">{m.model}</TableCell>
                            <TableCell className="font-mono text-xs">{m.accuracy.toFixed(4)}</TableCell>
                            <TableCell className="font-mono text-xs">{m.balancedAcc.toFixed(4)}</TableCell>
                            <TableCell className="font-mono text-xs">{m.precision.toFixed(4)}</TableCell>
                            <TableCell className="font-mono text-xs">{m.recall.toFixed(4)}</TableCell>
                            <TableCell className="font-mono text-xs">{m.f1.toFixed(4)}</TableCell>
                            <TableCell className="font-mono text-xs">{m.auc.toFixed(4)}</TableCell>
                            <TableCell className="font-mono text-xs font-semibold">{m.mcc.toFixed(4)}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </ScrollArea>
                </CardContent>
              </Card>

              <Card className="shadow-sm">
                <CardHeader>
                  <CardTitle className="text-base">Metric Comparison</CardTitle>
                  <CardDescription>Honest metrics across the three classifiers</CardDescription>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={280}>
                    <BarChart data={MODEL_METRICS} margin={{ left: 0, right: 20, top: 0, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" vertical={false} />
                      <XAxis dataKey="model" tick={{ fontSize: 11 }} />
                      <YAxis domain={[0.8, 1.0]} tick={{ fontSize: 11 }} />
                      <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8 }} />
                      <Legend wrapperStyle={{ fontSize: 11 }} />
                      <Bar dataKey="balancedAcc" name="Bal. Acc." fill="#0891b2" />
                      <Bar dataKey="f1" name="F1" fill="#65a30d" />
                      <Bar dataKey="auc" name="AUC" fill="#7c3aed" />
                      <Bar dataKey="mcc" name="MCC" fill="#dc2626" />
                    </BarChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </div>

            {/* Cross-validation with explanatory note */}
            <Card className="shadow-sm">
              <CardHeader>
                <CardTitle className="text-base">5-Fold Cross-Validation</CardTitle>
                <CardDescription className="space-y-1">
                  <span>Mean ± standard deviation across 5 stratified folds on the full labelled dataset.</span>
                  <span className="block text-xs text-muted-foreground">
                    <strong>What ± means:</strong> the value before ± is the average metric across 5 folds; the value after ± is the standard deviation (how much the metric varied fold-to-fold). <strong>Smaller ± = more stable model.</strong> For example, Linear SVM&rsquo;s MCC of 0.8742 ± 0.0155 means MCC stayed between 0.8587 and 0.8897 across all 5 folds.
                  </span>
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="max-h-72 rounded-md border">
                  <Table>
                    <TableHeader className="sticky top-0 bg-background">
                      <TableRow>
                        <TableHead>Model</TableHead>
                        <TableHead>Balanced Acc. (mean ± std)</TableHead>
                        <TableHead>F1 (mean ± std)</TableHead>
                        <TableHead>MCC (mean ± std)</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {CROSS_VALIDATION.map((m) => (
                        <TableRow key={m.model}>
                          <TableCell className="font-medium text-xs">{m.model}</TableCell>
                          <TableCell className="font-mono text-xs">
                            <span className="text-foreground">{m.balancedAcc.toFixed(4)}</span>
                            <span className="text-muted-foreground"> ± {m.balancedStd.toFixed(4)}</span>
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            <span className="text-foreground">{m.f1.toFixed(4)}</span>
                            <span className="text-muted-foreground"> ± {m.f1Std.toFixed(4)}</span>
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            <span className="text-foreground">{m.mcc.toFixed(4)}</span>
                            <span className="text-muted-foreground"> ± {m.mccStd.toFixed(4)}</span>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              </CardContent>
            </Card>

            {/* Per-attack-type + Feature importances (side by side on large screens) */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <Card className="shadow-sm">
                <CardHeader>
                  <CardTitle className="text-base">Per-Attack-Type (RF Multi-Class)</CardTitle>
                  <CardDescription>Precision / Recall / F1 by attack family</CardDescription>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="max-h-96 rounded-md border">
                    <Table>
                      <TableHeader className="sticky top-0 bg-background">
                        <TableRow>
                          <TableHead>Class</TableHead>
                          <TableHead>Prec.</TableHead>
                          <TableHead>Rec.</TableHead>
                          <TableHead>F1</TableHead>
                          <TableHead>Support</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {PER_CLASS_METRICS.map((m) => (
                          <TableRow key={m.class}>
                            <TableCell className="font-mono text-xs">{m.class}</TableCell>
                            <TableCell className="font-mono text-xs">{m.precision.toFixed(2)}</TableCell>
                            <TableCell className="font-mono text-xs">{m.recall.toFixed(2)}</TableCell>
                            <TableCell className="font-mono text-xs">{m.f1.toFixed(2)}</TableCell>
                            <TableCell className="font-mono text-xs">{m.support}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </ScrollArea>
                </CardContent>
              </Card>

              <Card className="shadow-sm">
                <CardHeader>
                  <CardTitle className="text-base">Top 10 Feature Importances</CardTitle>
                  <CardDescription>Approximate Random Forest feature importances</CardDescription>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={320}>
                    <BarChart data={FEATURE_IMPORTANCES} layout="vertical" margin={{ left: 30, right: 20, top: 0, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                      <XAxis type="number" tick={{ fontSize: 11 }} />
                      <YAxis dataKey="feature" type="category" width={140} tick={{ fontSize: 11 }} />
                      <Tooltip contentStyle={{ fontSize: 12, borderRadius: 8 }} formatter={(v: number) => [v.toFixed(3), "Importance"]} />
                      <Bar dataKey="importance" fill="#7c3aed" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </div>

            {/* Attack taxonomy */}
            <Card className="shadow-sm">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <BookOpen className="h-4 w-4" />
                  Attack Family Taxonomy
                </CardTitle>
                <CardDescription>The 12 attack families recognised by the labeller</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="max-h-96 overflow-auto rounded-md border">
                  <Table className="table-fixed w-full">
                    <TableHeader className="sticky top-0 bg-background z-10">
                      <TableRow>
                        <TableHead className="w-[28%]">Family</TableHead>
                        <TableHead className="w-[57%]">Description</TableHead>
                        <TableHead className="w-[15%]">Severity</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {ATTACK_TAXONOMY.map((t) => (
                        <TableRow key={t.family}>
                          <TableCell className="font-mono text-xs break-all align-top">
                            {t.family}
                          </TableCell>
                          <TableCell className="text-xs break-words align-top">
                            {t.description}
                          </TableCell>
                          <TableCell className="align-top">
                            <Badge variant="secondary" className={`text-[10px] ${SEVERITY_BADGE[t.severity] || ""}`}>
                              {t.severity}
                            </Badge>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t bg-background mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 text-center text-xs text-muted-foreground">
          <p>
            <strong>IS-212 Data &amp; Knowledge Mining Project</strong> — Log-Based Web Attack Classification
          </p>
          <p className="mt-1">
            Apache combined log format · 39 ground-truth rules + OWASP extensions · random_state=42
          </p>
        </div>
      </footer>
    </div>
  );
}

// ============ Sub-components ============

function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {[1, 2, 3, 4].map((i) => (
          <Skeleton key={i} className="h-28 w-full" />
        ))}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {[1, 2, 3, 4].map((i) => (
          <Skeleton key={i} className="h-80 w-full" />
        ))}
      </div>
      <Skeleton className="h-96 w-full" />
    </div>
  );
}

function ExplorePanel({
  results,
  loading,
}: {
  results: ClassificationResult[];
  loading: boolean;
}) {
  const [labelFilter, setLabelFilter] = useState<string>("all");
  const [methodFilter, setMethodFilter] = useState<string>("all");
  const [search, setSearch] = useState<string>("");

  const labels = Array.from(new Set(results.map((r) => r.label.label)));
  const methods = Array.from(new Set(results.map((r) => r.parsed.method)));

  const filtered = results.filter((r) => {
    if (labelFilter !== "all" && r.label.label !== labelFilter) return false;
    if (methodFilter !== "all" && r.parsed.method !== methodFilter) return false;
    if (search && !r.parsed.url.toLowerCase().includes(search.toLowerCase()) && !r.parsed.ip.includes(search)) return false;
    return true;
  });

  if (loading) return <Skeleton className="h-96 w-full" />;

  return (
    <div className="space-y-4">
      <Card className="shadow-sm">
        <CardContent className="py-4 flex flex-wrap gap-3 items-end">
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Attack family</label>
            <select
              value={labelFilter}
              onChange={(e) => setLabelFilter(e.target.value)}
              className="text-xs border rounded px-2 py-1.5 bg-background min-w-[160px]"
            >
              <option value="all">All families</option>
              {labels.sort().map((l) => (
                <option key={l} value={l}>{l}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">HTTP method</label>
            <select
              value={methodFilter}
              onChange={(e) => setMethodFilter(e.target.value)}
              className="text-xs border rounded px-2 py-1.5 bg-background min-w-[100px]"
            >
              <option value="all">All methods</option>
              {methods.sort().map((m) => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
          </div>
          <div className="flex-1 min-w-[200px]">
            <label className="text-xs text-muted-foreground block mb-1">Search URL or IP</label>
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="e.g. union, ../, 45.133.1.12"
              className="text-xs border rounded px-2 py-1.5 bg-background w-full"
            />
          </div>
          <Badge variant="outline" className="text-xs">
            {filtered.length} of {results.length}
          </Badge>
        </CardContent>
      </Card>

      <ResultsTable results={filtered} showOnlyAttacks={false} maxRows={500} />
    </div>
  );
}
