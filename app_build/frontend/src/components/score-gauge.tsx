import type { Grade } from "@/types";

const gradeColors: Record<Grade, string> = {
  A: "text-foreground",
  B: "text-foreground",
  C: "text-sev-medium",
  D: "text-sev-high",
  F: "text-sev-critical",
};

const strokeColors: Record<Grade, string> = {
  A: "#0E1116",
  B: "#0E1116",
  C: "#946005",
  D: "#c2410c",
  F: "#b91c1c",
};

export function ScoreGauge({ score, grade }: { score: number | null | undefined; grade: Grade | null | undefined }) {
  const r = 54;
  const circ = 2 * Math.PI * r;
  const validScore = typeof score === "number" && !isNaN(score);
  const pct = validScore ? score / 100 : 0;
  const offset = circ * (1 - pct);
  const activeColor = grade && strokeColors[grade] ? strokeColors[grade] : "#A3A099";
  const textColor = grade && gradeColors[grade] ? gradeColors[grade] : "text-muted";

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-32 h-32">
        <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
          <circle cx="60" cy="60" r={r} fill="none" stroke="#DAD8D2" strokeWidth="8" />
          {validScore && (
            <circle
              cx="60" cy="60" r={r} fill="none"
              stroke={activeColor}
              strokeWidth="8"
              strokeDasharray={circ}
              strokeDashoffset={offset}
              strokeLinecap="round"
            />
          )}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold tabular-nums">{validScore ? score : "—"}</span>
          <span className={`text-lg font-bold ${textColor}`}>{grade ?? "N/A"}</span>
        </div>
      </div>
      <p className="text-xs text-muted mt-2">Posture score</p>
    </div>
  );
}
