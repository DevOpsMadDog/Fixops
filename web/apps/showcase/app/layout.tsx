import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "FixOps Showcase - Security Decision Automation Platform",
  description: "Interactive demonstration of FixOps capabilities with real security data",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
