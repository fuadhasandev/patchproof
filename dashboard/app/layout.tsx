import type { Metadata } from 'next';
import './globals.css';
export const metadata: Metadata = {title: 'PatchProof · Website security checker', description: 'Check website security configuration, understand findings, and compare checks after a fix.'};
export default function RootLayout({ children }: {children: React.ReactNode}) {
  return <html lang="en"><body>{children}</body></html>;
}
