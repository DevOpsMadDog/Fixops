/**
 * ExportButton — CSV and JSON export for data tables.
 *
 * Usage:
 *   <ExportButton data={rows} filename="alert-triage" />
 *
 * Props:
 *   data      — array of plain objects (the table rows)
 *   filename  — base filename without extension (e.g. "vuln-scans")
 *   className — optional extra classes for the wrapper div
 */

import { Download } from "lucide-react";
import { Button } from "@/components/ui/button";

interface ExportButtonProps {
  data: Record<string, unknown>[];
  filename: string;
  className?: string;
}

function flattenValue(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (Array.isArray(v)) return v.join("; ");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function escapeCsvCell(raw: string): string {
  // Wrap in quotes if value contains comma, quote, or newline
  if (raw.includes(",") || raw.includes('"') || raw.includes("\n")) {
    return `"${raw.replace(/"/g, '""')}"`;
  }
  return raw;
}

export function ExportButton({ data, filename, className }: ExportButtonProps) {
  const exportCSV = () => {
    if (!data.length) return;
    const headers = Object.keys(data[0]);
    const headerRow = headers.map(escapeCsvCell).join(",");
    const rows = data
      .map((row) =>
        headers.map((h) => escapeCsvCell(flattenValue(row[h]))).join(",")
      )
      .join("\n");
    const blob = new Blob([headerRow + "\n" + rows], { type: "text/csv;charset=utf-8;" });
    triggerDownload(blob, `${filename}.csv`);
  };

  const exportJSON = () => {
    if (!data.length) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    triggerDownload(blob, `${filename}.json`);
  };

  return (
    <div className={`flex items-center gap-1 ${className ?? ""}`}>
      <Button
        variant="outline"
        size="sm"
        onClick={exportCSV}
        disabled={!data.length}
        className="h-8 gap-1.5 text-xs"
        title="Export as CSV"
      >
        <Download className="h-3.5 w-3.5" />
        CSV
      </Button>
      <Button
        variant="outline"
        size="sm"
        onClick={exportJSON}
        disabled={!data.length}
        className="h-8 gap-1.5 text-xs"
        title="Export as JSON"
      >
        <Download className="h-3.5 w-3.5" />
        JSON
      </Button>
    </div>
  );
}

// ── Helper ─────────────────────────────────────────────────────

function triggerDownload(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
