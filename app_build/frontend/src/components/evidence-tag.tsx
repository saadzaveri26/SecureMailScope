export function EvidenceTag({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center px-1.5 py-0.5 rounded-[var(--radius-xs)] bg-surface-base text-white font-mono font-bold text-[11px] leading-none shrink-0">
      {children}
    </span>
  );
}
