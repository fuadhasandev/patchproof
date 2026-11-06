import type { Metadata } from 'next';
import './globals.css';
export const metadata: Metadata = {title: 'PatchProof · Local security workbench', description: 'Evidence first. Verify every fix.'};
export default function RootLayout({ children }: {children: React.ReactNode}) {
  return <html lang="en"><body>{children}</body></html>;
}
