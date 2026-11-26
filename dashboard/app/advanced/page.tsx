import LocalDashboard from '../LocalDashboard';
import HostedDashboard from '../HostedDashboard';
export const dynamic = 'force-dynamic';
export default function Home() {
  return <><a className="back-link" href="/">Back to website checker</a>{process.env.PATCHPROOF_MODE === 'hosted' ? <HostedDashboard/> : <LocalDashboard/>}</>;
}
