import type { Metadata } from "next";
import "./globals.css";
import { AuthProvider } from "@/lib/auth-context";

export const metadata: Metadata = {
  title: "SentinelAI \u2014 EDR Dashboard",
  description: "AI-Powered Endpoint Detection & Response Platform",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link
          href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="bg-cyber-bg text-cyber-text antialiased font-mono">
        <div className="scanline-overlay" />
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
