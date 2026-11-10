import LocalDashboard from './LocalDashboard';
import HostedDashboard from './HostedDashboard';
export const dynamic = 'force-dynamic';
export default function Home() {
  return process.env.PATCHPROOF_MODE === 'hosted' ? <HostedDashboard/> : <LocalDashboard/>;
}
