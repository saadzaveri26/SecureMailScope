export function EvidenceTag({
  children,
  variant = "yellow",
}: {
  children: React.ReactNode;
  variant?: "yellow" | "dark";
}) {
  const cls =
    variant === "yellow"
      ? "bg-amber-300 text-neutral-950 border border-amber-400 font-bold"
      : "bg-surface-base text-white";
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded-[var(--radius-xs)] font-mono text-[11px] leading-none shrink-0 ${cls}`}>
      {children}
    </span>
  );
}
