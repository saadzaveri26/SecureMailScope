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
      <header className="bg-white border-b-2 border-black select-none h-11">
        <div className="max-w-[1600px] mx-auto px-4 flex items-center h-full justify-between gap-4">
          <div className="flex items-center h-full gap-5">
            <Link href="/" className="flex items-center gap-1.5 text-black font-bold text-sm tracking-tight font-mono shrink-0">
              <span className="text-accent">▸</span>
              <span>SecureMailScope</span>
              <span className="text-[10px] text-muted font-normal">v1.0</span>
            </Link>

            <div className="w-0.5 h-5 bg-black" />

            <nav className="flex items-center h-full gap-0">
              {links.map(({ href, label }) => {
                const active = path.startsWith(href);
                return (
                  <Link
                    key={href}
                    href={href}
                    className={[
                      "h-11 flex items-center px-2.5 text-xs font-mono border-b-3 transition-colors",
                      active
                        ? "border-accent text-black font-bold bg-accent/10"
                        : "border-transparent text-muted hover:text-foreground",
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
            className="flex items-center gap-1.5 px-3 py-1.5 bg-accent hover:bg-accent-hover border-2 border-black text-black text-xs font-mono font-bold transition-all brutal-shadow-sm brutal-shadow-hover shrink-0"
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
