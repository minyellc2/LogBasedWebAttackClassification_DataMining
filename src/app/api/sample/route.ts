import { NextResponse } from "next/server";
import {
  SAMPLE_LOG_LINES,
  classifyLines,
  summarize,
  type ClassificationResult,
} from "@/lib/engine/classifier";

// GET /api/sample
// Returns the built-in sample dataset with classifications + summary.
export async function GET() {
  const { results, unparseable } = classifyLines(SAMPLE_LOG_LINES);
  const summary = summarize(results, unparseable.length);

  // Trim raw lines from results to keep response size manageable
  const trimmed: ClassificationResult[] = results.map((r) => ({
    parsed: r.parsed,
    features: r.features,
    label: r.label,
  }));

  return NextResponse.json({
    summary,
    results: trimmed,
    totalLines: SAMPLE_LOG_LINES.length,
  });
}
