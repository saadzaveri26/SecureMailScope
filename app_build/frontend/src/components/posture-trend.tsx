"use client";

import type { Capture } from "@/types";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";

export function PostureTrend({ captures }: { captures: Capture[] }) {
  const data = captures
    .filter((c) => c.posture_score !== null)
    .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
    .map((c) => ({
      name: new Date(c.created_at).toLocaleDateString("en-US", { month: "short", day: "numeric" }),
      score: c.posture_score,
      grade: c.grade,
    }));

  if (data.length < 2) return null;

  return (
    <div className="h-48">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 4, right: 12, bottom: 4, left: 12 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#DAD8D2" />
          <XAxis dataKey="name" tick={{ fontSize: 11, fill: "#4B5563" }} />
          <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: "#4B5563" }} width={32} />
          <Tooltip
            contentStyle={{
              fontSize: 12,
              borderRadius: 4,
              border: "1px solid #DAD8D2",
              boxShadow: "none",
            }}
            formatter={(v: unknown, _n: unknown, p: unknown) => {
              const entry = p as { payload?: { grade?: string } };
              return [`${v} (${entry?.payload?.grade ?? ""})`, "Score"];
            }}
          />
          <Line
            type="monotone"
            dataKey="score"
            stroke="#0E1116"
            strokeWidth={2}
            dot={{ r: 4, fill: "#0E1116" }}
            activeDot={{ r: 6 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
