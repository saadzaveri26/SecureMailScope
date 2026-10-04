import type { Metadata } from "next";
import { Suspense } from "react";
import { Inter, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";
import { Nav } from "@/components/nav";
import { AuthProvider } from "@/components/auth-context";
import { AuthGate } from "@/components/auth-gate";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
});

const plexMono = IBM_Plex_Mono({
  variable: "--font-plex-mono",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
});

export const metadata: Metadata = {
  title: "SecureMailScope",
  description: "Passive cryptographic posture assessment of email traffic",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${plexMono.variable} h-full`}
    >
      <body className="min-h-full flex flex-col bg-background text-foreground">
        <AuthProvider>
          <AuthGate>
            <Suspense>
              <Nav />
            </Suspense>
            <main className="flex-1">{children}</main>
          </AuthGate>
        </AuthProvider>
      </body>
    </html>
  );
}
