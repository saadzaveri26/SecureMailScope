"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { CaptureStrip } from "./capture-strip";

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
      <header className="bg-ink">
        <div className="max-w-[1400px] mx-auto px-4 flex items-center h-12 justify-between gap-6">
          <div className="flex items-center h-full gap-8">
            <Link href="/" className="text-evidence font-semibold text-sm tracking-tight shrink-0">
              SecureMailScope
            </Link>

            <nav className="flex items-center h-full gap-0.5">
              {links.map(({ href, label }) => {
                const active = path.startsWith(href);
                return (
                  <Link
                    key={href}
                    href={href}
                    className={[
                      "h-12 flex items-center px-3 text-xs transition-colors border-b-2",
                      active
                        ? "border-evidence text-white font-medium"
                        : "border-transparent text-white/60 hover:text-white/90",
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
            className="px-3.5 py-1.5 rounded-sm bg-evidence hover:bg-evidence/90 text-ink text-xs font-bold transition-colors shrink-0 focus:outline-none focus:ring-2 focus:ring-ink focus:ring-offset-2 focus:ring-offset-evidence"
          >
            Upload PCAP
          </Link>
        </div>
      </header>
      <CaptureStrip />
    </>
  );
}
