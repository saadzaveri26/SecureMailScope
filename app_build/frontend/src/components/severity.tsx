"use client";

import type { Severity } from "@/types";
import {
  XCircle,
  WarningOctagon,
  Warning,
  Info,
  CheckCircle,
  type Icon,
} from "@phosphor-icons/react";

const cfg: Record<Severity | "pass", { icon: Icon; text: string; label: string }> = {
  critical: { icon: XCircle, text: "text-sev-critical", label: "Critical" },
  high: { icon: WarningOctagon, text: "text-sev-high", label: "High" },
  medium: { icon: Warning, text: "text-sev-medium", label: "Medium" },
  low: { icon: Info, text: "text-sev-low", label: "Low" },
  info: { icon: Info, text: "text-sev-info", label: "Info" },
  pass: { icon: CheckCircle, text: "text-sev-pass", label: "Pass" },
};

export function SeverityBadge({ severity }: { severity: Severity | "pass" }) {
  const c = cfg[severity];
  const Icon = c.icon;
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${c.text}`}>
      <Icon size={14} weight="bold" />
      {c.label}
    </span>
  );
}

export function SeverityDot({ severity }: { severity: Severity }) {
  const c = cfg[severity];
  return <span className={`inline-block w-2 h-2 rounded-[2px] ${c.text} bg-current`} />;
}
