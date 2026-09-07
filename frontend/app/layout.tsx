import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SecureOps RAG Assistant",
  description: "Grounded ICS and OT cybersecurity intelligence from CISA and NIST sources.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
