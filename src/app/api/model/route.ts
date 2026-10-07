import { NextResponse } from "next/server";
import {
  MODEL_METRICS,
  CROSS_VALIDATION,
  PER_CLASS_METRICS,
  FEATURE_IMPORTANCES,
  ATTACK_TAXONOMY,
  RULES,
  SUSPICIOUS_KEYWORDS,
} from "@/lib/engine/classifier";

// GET /api/model
// Returns model evaluation results, feature importances, attack taxonomy, and rule inventory.
export async function GET() {
  return NextResponse.json({
    models: MODEL_METRICS,
    crossValidation: CROSS_VALIDATION,
    perClass: PER_CLASS_METRICS,
    featureImportances: FEATURE_IMPORTANCES,
    attackTaxonomy: ATTACK_TAXONOMY,
    rules: RULES.map((r) => ({
      id: r.id,
      label: r.label,
      patterns: r.patterns,
      matchMode: r.patterns.length > 1 ? "AND" : "OR",
    })),
    keywords: SUSPICIOUS_KEYWORDS,
  });
}
