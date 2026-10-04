"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
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

  return (
    <>
      <header className="bg-surface-base select-none h-11" role="banner">
        <div className="max-w-[1600px] mx-auto px-4 flex items-center h-full justify-between gap-4">
          <div className="flex items-center h-full gap-5">
            <Link
              href="/"
              className="flex items-center gap-1.5 text-white font-bold text-sm tracking-tight shrink-0 focus-ring"
            >
              <span className="text-accent">▸</span>
              <span>SecureMailScope</span>
              <span className="text-[10px] text-white/50 font-normal">v1.0</span>
            </Link>

            <div className="w-px h-5 bg-white/20" />

            <nav className="flex items-center h-full gap-0" role="navigation" aria-label="Main navigation">
              {links.map(({ href, label }) => {
                const active = path.startsWith(href);
                return (
                  <Link
                    key={href}
                    href={href}
                    aria-current={active ? "page" : undefined}
                    className={[
                      "h-11 flex items-center px-2.5 text-[var(--font-size-md)] font-medium border-b-2 focus-ring",
                      `transition-colors duration-[var(--motion-fast)]`,
                      active
                        ? "border-accent text-white font-bold"
                        : "border-transparent text-white/60 hover:text-white",
                    ].join(" ")}
                  >
                    {label}
                  </Link>
                );
              })}
            </nav>
          </div>

          <Link
            href="/captures"
            className={[
              "flex items-center gap-1.5 px-3 py-1.5 text-white text-[var(--font-size-md)] font-bold shrink-0",
              "bg-accent hover:bg-accent-hover rounded-[var(--radius-sm)]",
              "transition-all duration-[var(--motion-fast)]",
              "active:scale-[0.97] focus-ring",
            ].join(" ")}
          >
            <UploadSimple size={12} weight="bold" />
            <span>Ingest PCAP</span>
          </Link>
        </div>
      </header>
      <CaptureStrip />
    </>
  );
}
