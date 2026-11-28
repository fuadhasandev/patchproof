import LocalDashboard from '../LocalDashboard';
import HostedDashboard from '../HostedDashboard';
export const dynamic = 'force-dynamic';
export default function Home() {
  // The Vercel checker deployment cannot run the local or hosted workbench.
  if (process.env.VERCEL === '1') {
    return (
      <>
        <header className="topbar">
          <a className="brand" href="/">PatchProof</a>
        </header>
        <main className="checker">
          <section className="panel" aria-labelledby="advanced-heading">
            <p className="eyebrow">Advanced features</p>
            <h1 id="advanced-heading">Advanced dashboard availability</h1>
            <p>Advanced features are available in the local dashboard and in supported authenticated hosted deployments.</p>
            <p>This deployment offers the website checker. The Advanced workbench and local scan history are not available here.</p>
            <a className="button" href="/">Back to website checker</a>
          </section>
        </main>
      </>
    );
  }

  return <><a className="back-link" href="/">Back to website checker</a>{process.env.PATCHPROOF_MODE === 'hosted' ? <HostedDashboard/> : <LocalDashboard/>}</>;
}
