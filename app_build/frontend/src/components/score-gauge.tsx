import type { Grade } from "@/types";

const gradeColors: Record<Grade, string> = {
  A: "text-foreground",
  B: "text-foreground",
  C: "text-sev-medium",
  D: "text-sev-high",
  F: "text-sev-critical",
};

const strokeColors: Record<Grade, string> = {
  A: "#475569",
  B: "#475569",
  C: "#a16207",
  D: "#c2410c",
  F: "#b91c1c",
};

export function ScoreGauge({ score, grade }: { score: number; grade: Grade }) {
  const r = 54;
  const circ = 2 * Math.PI * r;
  const pct = score / 100;
  const offset = circ * (1 - pct);

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-32 h-32">
        <svg viewBox="0 0 120 120" className="w-full h-full -rotate-90">
          <circle cx="60" cy="60" r={r} fill="none" stroke="#e2e4e8" strokeWidth="8" />
          <circle
            cx="60" cy="60" r={r} fill="none"
            stroke={strokeColors[grade]}
            strokeWidth="8"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold tabular-nums">{score}</span>
          <span className={`text-lg font-bold ${gradeColors[grade]}`}>{grade}</span>
        </div>
      </div>
      <p className="text-xs text-muted mt-2">Posture score</p>
    </div>
  );
}
