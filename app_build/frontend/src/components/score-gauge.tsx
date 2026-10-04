import type { Grade } from "@/types";

const gradeColors: Record<Grade, string> = {
  A: "text-sev-pass",
  B: "text-foreground",
  C: "text-sev-medium",
  D: "text-sev-high",
  F: "text-sev-critical",
};

const strokeColors: Record<Grade, string> = {
  A: "#16a34a",
  B: "#141414",
  C: "#a16207",
  D: "#ea580c",
  F: "#dc2626",
};

export function ScoreGauge({ score, grade }: { score: number | null | undefined; grade: Grade | null | undefined }) {
  const r = 54;
  const circ = 2 * Math.PI * r;
  const validScore = typeof score === "number" && !isNaN(score);
  const pct = validScore ? score / 100 : 0;
  const offset = circ * (1 - pct);
  const activeColor = grade && strokeColors[grade] ? strokeColors[grade] : "#adb5bd";
  const textColor = grade && gradeColors[grade] ? gradeColors[grade] : "text-muted";

  const ariaLabel = validScore
    ? `Posture score: ${score} out of 100, grade ${grade}`
    : "Posture score: not available";

  return (
    <div className="flex flex-col items-center">
      <div
        className="relative w-32 h-32"
        role="img"
        aria-label={ariaLabel}
      >
        <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
          <circle cx="60" cy="60" r={r} fill="none" stroke="var(--color-surface-2)" strokeWidth="8" />
          {validScore && (
            <circle
              cx="60" cy="60" r={r} fill="none"
              stroke={activeColor}
              strokeWidth="8"
              strokeDasharray={circ}
              strokeDashoffset={offset}
              strokeLinecap="round"
              className="transition-all duration-[var(--motion-slower)]"
            />
          )}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold tabular-nums text-foreground">{validScore ? score : "—"}</span>
          <span className={`text-lg font-bold ${textColor}`}>{grade ?? "N/A"}</span>
        </div>
      </div>
      <p className="text-[var(--font-size-sm)] text-muted mt-2">Posture score</p>
    </div>
  );
}
