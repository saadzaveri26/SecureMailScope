export function EvidenceTag({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center px-1.5 py-0.5 rounded-[2px] bg-evidence text-ink font-mono font-bold text-[11px] leading-none shrink-0">
      {children}
    </span>
  );
}
