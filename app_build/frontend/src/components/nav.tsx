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
  const isDemo = process.env.NEXT_PUBLIC_DEMO_MODE === "1" || process.env.NEXT_PUBLIC_DEMO_MODE === "true";

  return (
    <>
      <header className="bg-surface-0 border-b border-border">
        <div className="max-w-[1400px] mx-auto px-4 flex items-center h-14 justify-between gap-6">
          <div className="flex items-center h-full gap-8">
            <Link href="/" className="text-brand font-semibold text-sm tracking-tight shrink-0">
              SecureMailScope
            </Link>

            <nav className="flex items-center h-full gap-1">
              {links.map(({ href, label }) => {
                const active = path.startsWith(href);
                return (
                  <Link
                    key={href}
                    href={href}
                    className={[
                      "h-14 flex items-center px-3 text-sm transition-colors border-b-2",
                      active
                        ? "border-brand text-brand font-medium"
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
            href={isDemo ? "/overview?capture=cap-001" : "/captures"}
            className="px-3.5 py-1.5 rounded-md bg-brand hover:bg-brand-hover text-white text-xs font-semibold transition-colors shrink-0"
          >
            {isDemo ? "Open the sample analysis" : "Upload PCAP"}
          </Link>
        </div>
      </header>
      <CaptureStrip />
    </>
  );
}
