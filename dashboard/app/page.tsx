import WebsiteChecker from './WebsiteChecker';
export const dynamic = 'force-dynamic';
export default function Home() {
  return <WebsiteChecker hosted={process.env.PATCHPROOF_MODE === 'hosted'}/>;
}
