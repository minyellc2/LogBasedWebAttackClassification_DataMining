import { NextResponse } from "next/server";
import { classifyLines, summarize, type ClassificationResult } from "@/lib/engine/classifier";

// POST /api/classify
// Body: { "lines": string[] } | { "text": string } — Apache access log lines
// Returns: per-entry classification + aggregates
export async function POST(request: Request) {
  let body: { lines?: string[]; text?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  // Accept either an explicit array of lines or a multi-line text blob
  let lines: string[] = [];
  if (Array.isArray(body.lines)) {
    lines = body.lines;
  } else if (typeof body.text === "string") {
    lines = body.text.split(/\r?\n/);
  } else {
    return NextResponse.json(
      { error: "Request must include 'lines' (string[]) or 'text' (string)." },
      { status: 400 }
    );
  }

  const totalInputLines = lines.filter((l) => l.trim()).length;

  // Cap at 10,000 lines to keep the response snappy
  const MAX = 10_000;
  const truncated = totalInputLines > MAX;
  const working = truncated ? lines.slice(0, MAX) : lines;

  const { results, unparseable } = classifyLines(working);
  const summary = summarize(results, unparseable.length);

  const trimmed: ClassificationResult[] = results.map((r) => ({
    parsed: r.parsed,
    features: r.features,
    label: r.label,
  }));

  return NextResponse.json({
    summary,
    results: trimmed,
    unparseable: unparseable.slice(0, 50), // first 50 for visibility
    truncated,
    maxLines: MAX,
    totalInputLines,
    parsedLines: results.length,
  });
}
