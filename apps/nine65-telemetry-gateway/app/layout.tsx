import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "NINE65 Telemetry Gateway",
  description:
    "Ciphertext-only telemetry gateway wired to a Rust NINE65 FHE service boundary"
};

export default function RootLayout({
  children
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
