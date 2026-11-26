import WebsiteChecker from './WebsiteChecker';
export const dynamic = 'force-dynamic';
export default function Home() {
  return <WebsiteChecker basic={!!process.env.PATCHPROOF_BASIC_BACKEND_URL} hosted={process.env.PATCHPROOF_MODE === 'hosted'}/>;
}
