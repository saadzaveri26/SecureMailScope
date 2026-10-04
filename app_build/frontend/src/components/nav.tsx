"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { CaptureStrip } from "./capture-strip";
import { UploadSimple } from "@phosphor-icons/react";

const links = [
  { href: "/captures", label: "Captures" },
  { href: "/overview", label: "Overview" },
  { href: "/sessions", label: "Sessions" },
  { href: "/findings", label: "Findings" },
  { href: "/drift", label: "Drift" },
  { href: "/evaluation", label: "Evaluation" },
  { href: "/reports", label: "Reports" },
];

export function Nav() {
  const path = usePathname();
  const searchParams = useSearchParams();
  const isDemo = process.env.NEXT_PUBLIC_USE_FIXTURES === "1" || process.env.NEXT_PUBLIC_DEMO_MODE === "1";
  const currentCap = searchParams?.get("capture") ?? searchParams?.get("current") ?? "cap-001";
  const nextCap = currentCap === "cap-001" ? "cap-002" : "cap-001";
  const cycleUrl = path === "/" ? `/overview?capture=${nextCap}` : `${path}?capture=${nextCap}`;

  return (
    <>
      <header className="bg-surface-base select-none h-12" role="banner">
        <div className="w-full px-4 2xl:px-6 flex items-center h-full justify-between gap-4">
          <div className="flex items-center h-full gap-5">
            <Link
              href="/"
              className="flex items-center gap-1.5 text-white font-semibold text-[14px] shrink-0 focus-ring"
            >
              <span className="text-accent">▸</span>
              <span>SecureMailScope</span>
              <span className="text-[11px] text-white/50 font-normal">v1.0</span>
            </Link>

            <div className="w-px h-4 bg-white/20" />

            <nav className="flex items-center h-full gap-0" role="navigation" aria-label="Main navigation">
              {links.map(({ href, label }) => {
                const active = path.startsWith(href);
                return (
                  <Link
                    key={href}
                    href={href}
                    aria-current={active ? "page" : undefined}
                    className={[
                      "h-12 flex items-center px-3 text-[13px] border-b-2 focus-ring",
                      active
                        ? "border-accent text-white font-semibold"
                        : "border-transparent text-white/70 hover:text-white font-medium",
                    ].join(" ")}
                  >
                    {label}
                  </Link>
                );
              })}
            </nav>
          </div>

          {isDemo ? (
            <Link
              href={cycleUrl}
              className="flex items-center gap-1.5 px-3 py-1.5 text-white text-[13px] font-semibold shrink-0 bg-accent hover:bg-accent-hover rounded-[var(--radius-sm)] transition-colors focus-ring"
            >
              Sample analysis
            </Link>
          ) : (
            <Link
              href="/#upload"
              className="flex items-center gap-1.5 px-3 py-1.5 text-white text-[13px] font-semibold shrink-0 bg-accent hover:bg-accent-hover rounded-[var(--radius-sm)] transition-colors focus-ring"
            >
              <UploadSimple size={14} weight="bold" />
              <span>Upload PCAP</span>
            </Link>
          )}
        </div>
      </header>
      <CaptureStrip />
    </>
  );
}
