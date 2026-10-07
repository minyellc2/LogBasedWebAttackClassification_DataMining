# Log-Based Web Attack Classifier — Standalone Web UI

Interactive Next.js 16 web UI for classifying Apache access log entries as
benign or attack (and identifying the attack type), using the labelling rules
and feature engineering from the IS-212 project.

## Prerequisites

You need either **Node.js 18+** OR **Bun** installed on your machine.

### Option A — Node.js (recommended for most users)

Download from https://nodejs.org/ (pick the LTS version).

Verify:
```bash
node --version    # should print v18.x or higher
npm --version
```

### Option B — Bun (faster, smaller)

```bash
# macOS / Linux
curl -fsSL https://bun.sh/install | bash

# Windows: use PowerShell per https://bun.sh/docs/installation
```

## Setup

```bash
# 1. Unzip the project
unzip web-attack-classifier.zip
cd web-attack-classifier

# 2. Install dependencies (pick ONE)
npm install        # if you chose Node.js
# OR
bun install        # if you chose Bun

# 3. Start the dev server
npm run dev        # OR: bun run dev

# 4. Open in your browser
#   http://localhost:3000
```

You should see the dashboard load with 41 sample log lines pre-loaded
(23 attacks across 9 attack families).

## Using the UI

- **Dashboard** — KPIs + charts for the preloaded sample
- **Classify** — paste your own log lines or upload a `.log`/`.txt` file
  (up to 10,000 lines), click "Run Classifier", see per-entry predictions
- **Explore** — filterable table of all entries (by attack family, method, search)
- **Model** — binary metrics, 5-fold CV, per-attack-type, K-Means best-k chart,
  feature importances, attack family taxonomy

## Tech Stack

- Next.js 16 + TypeScript + Tailwind CSS 4 + shadcn/ui + Recharts
- The classifier engine is **pure TypeScript** — no Python or sklearn needed.
- Random forest metrics are pre-computed and embedded (from the notebook output).

## Production Build (optional)

For a faster, production-ready server:

```bash
npm run build
npm run start
# OR
bun run build
bun run start
```

## Project Structure

```
src/
  app/
    page.tsx           Main UI (4 tabs: Dashboard / Classify / Explore / Model)
    layout.tsx         Root layout with metadata
    api/
      sample/route.ts  GET — preloaded sample dataset
      classify/route.ts POST — classify uploaded/pasted logs
      model/route.ts   GET — model metrics + rule inventory
  components/
    dashboard/
      kpi-cards.tsx    KPI summary cards
      charts.tsx       Recharts visualizations
      results-table.tsx Per-entry classification table
    ui/                shadcn/ui components (Button, Card, Table, etc.)
  lib/
    engine/
      classifier.ts    Apache log parser + labeller + features + metrics
```

## Troubleshooting

- **Port already in use**: change `npm run dev` to `npm run dev -- -p 3001`
- **node-gyp errors on install**: install Python 3 + build tools (Windows: `npm install -g windows-build-tools`)
- **Blank page on first load**: check the terminal for compile errors; the
  Turbopack dev server shows the error in the browser

## Credits

IS-212 Data and Knowledge Mining Project — Log-Based Web Attack Classification.
Apache combined log format · 39 ground-truth rules + OWASP extensions ·
random_state=42 for reproducibility.
