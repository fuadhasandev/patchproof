import { Laptop, LockKeyhole, SlidersHorizontal, Search } from "lucide-react";
import type { Metadata } from "next";
import LocalDashboard from "../LocalDashboard";
import HostedDashboard from "../HostedDashboard";
export const dynamic = "force-dynamic";
export const metadata: Metadata = {
  title: "Advanced workbench",
  robots: {
    index: false,
    follow: false,
  },
};
const docs = "https://github.com/fuadhasandev/patchproof/blob/main";
export default function AdvancedPage() {
  // The Vercel checker deployment cannot run the local or hosted workbench.
  if (process.env.VERCEL === "1") {
    return (
      <>
        <a className="back-link" href="/">
          Back to website checker
        </a>
        <main id="main-content" className="availability">
          <div className="availability-intro">
            <span className="feature-icon">
              <SlidersHorizontal size={28} />
            </span>
            <p className="eyebrow">Advanced workbench</p>
            <h1>Go deeper with your own workspace.</h1>
            <p>
              Configure focused scans, inspect saved evidence, and replay
              individual checks after a fix.
            </p>
            <p>
              This deployment offers the website checker. The Advanced workbench
              and local scan history are not available here.
            </p>
            <a className="button" href="/">
              <Search size={17} />
              Back to website checker
            </a>
          </div>
          <div className="availability-grid">
            <section className="panel">
              <Laptop size={25} />
              <h2>On your machine</h2>
              <p>
                Run the local dashboard for scan history, named cookie checks,
                CheckSpec exports, and supported browser checks.
              </p>
              <span className="badge resolved">Local access only</span>
              <hr />
              <a href={`${docs}/README.md#api-and-dashboard`}>
                Set up the local dashboard
              </a>
            </section>
            <section className="panel">
              <LockKeyhole size={25} />
              <h2>In an authenticated deployment</h2>
              <p>
                Use verified domains and project-scoped reports through a
                supported hosted environment with sign-in.
              </p>
              <span className="badge unverified">Requires hosted setup</span>
              <hr />
              <a href={`${docs}/docs/production.md`}>
                Read the deployment guide
              </a>
            </section>
          </div>
          <p className="availability-note">
            Advanced features retain their authentication and local access
            requirements. Local scan history stays on your machine.
          </p>
        </main>
      </>
    );
  }
  return (
    <>
      <a className="back-link" href="/">
        Back to website checker
      </a>
      {process.env.PATCHPROOF_MODE === "hosted" ? (
        <HostedDashboard />
      ) : (
        <LocalDashboard />
      )}
    </>
  );
}
