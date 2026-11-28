import type { Metadata } from 'next';
import { siteUrl } from '@/lib/site-metadata';
import WebsiteChecker from './WebsiteChecker';
export const dynamic = 'force-dynamic';
export const metadata: Metadata = {
  alternates: {
    canonical: siteUrl,
  },
};
export default function Home() {
  return <WebsiteChecker basic={!!process.env.PATCHPROOF_BASIC_BACKEND_URL} hosted={process.env.PATCHPROOF_MODE === 'hosted'}/>;
}
