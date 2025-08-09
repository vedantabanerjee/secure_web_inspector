import type { Metadata } from 'next'
import { GeistSans } from 'geist/font/sans'
import { GeistMono } from 'geist/font/mono'
import './globals.css'

export const metadata: Metadata = {
  title: "SecureWeb Inspector",
  keywords: [
    "web security",
    "vulnerability scanning",
    "OWASP Top 10",
    "SSL analysis",
    "GDPR compliance",
    "security reports",
    "real-time analytics",
  ],
  description:
    "Web security scanning platform that performs real-time vulnerability assessments.",
  generator: "vedantabanerjee",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en">
      <head>
        <link rel="icon" href="securewebinspector.png" />
        <style>{`
html {
  font-family: ${GeistSans.style.fontFamily};
  --font-sans: ${GeistSans.variable};
  --font-mono: ${GeistMono.variable};
}
        `}</style>
      </head>
      <body>{children}</body>
    </html>
  );
}
