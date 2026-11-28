"use client";
import { useEffect, useRef, useState } from "react";
import {
  Search,
  ShieldCheck,
  ScanLine,
  FileSearch,
  RotateCw,
  GitFork,
  FlaskConical,
  LockKeyhole,
  LoaderCircle,
  CircleAlert,
  Terminal,
  Check,
} from "lucide-react";
import { Report } from "./components/Report";
import { repository } from "./components/SiteChrome";
import type { Job } from "@/lib/types";
import { checks, sampleJob } from "@/lib/check-report";

type Project = { id: string; name: string };
type Target = {
  id: string;
  hostname: string;
  verified_until: number;
  revoked: boolean;
};
type Challenge = {
  id: string;
  record: string;
  value: string;
  expires_at: number;
};
type Submission = {
  target_url: string;
  session_cookies: string[];
  ai: boolean;
  browser: boolean;
  project_id?: string;
  target_id?: string;
};
function responseError(status: number, detail: unknown) {
  if (status === 429)
    return "Request limit reached. Please wait before trying again, or explore the sample report.";
  if (status === 401) return "Sign in to your hosted account, then try again.";
  if (status >= 500)
    return "The check service is unavailable. Please try again shortly, or explore the sample report.";
  return typeof detail === "string"
    ? detail
    : "The request could not be completed. Check the URL and try again.";
}
export default function WebsiteChecker({
  hosted,
  basic = false,
}: {
  hosted: boolean;
  basic?: boolean;
}) {
  const [url, setUrl] = useState("");
  const [job, setJob] = useState<Job | null>(null);
  const [previous, setPrevious] = useState<Job | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [sample, setSample] = useState(false);
  const [submission, setSubmission] = useState<Submission | null>(null);
  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [pending, setPending] = useState<Submission | null>(null);
  const [progress, setProgress] = useState("");
  const keys = useRef(new Map<string, string>());
  const reportRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (job) {
      reportRef.current?.scrollIntoView({
        behavior: matchMedia("(prefers-reduced-motion: reduce)").matches
          ? "instant"
          : "smooth",
        block: "start",
      });
      document.getElementById("report")?.focus({ preventScroll: true });
    }
  }, [job]);
  async function request<T>(path: string, body?: unknown): Promise<T> {
    const signature = path + JSON.stringify(body);
    let key = keys.current.get(signature);
    if (body !== undefined && !key) {
      key = crypto.randomUUID();
      keys.current.set(signature, key);
    }
    const response = await fetch(
      "/api/" + (hosted ? "hosted/" : "") + path,
      body === undefined
        ? { cache: "no-store" }
        : {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              ...(hosted ? { "Idempotency-Key": key! } : {}),
            },
            body: JSON.stringify(body),
          },
    );
    const data = await response.json().catch(() => ({}));
    if (!response.ok)
      throw new Error(responseError(response.status, data.detail));
    keys.current.delete(signature);
    return data;
  }
  async function all<T>(path: string): Promise<T[]> {
    const items: T[] = [];
    let cursor: string | null = null;
    do {
      const page: { items: T[]; next_cursor: string | null } = await request(
        path + (cursor ? "?before=" + cursor : ""),
      );
      items.push(...page.items);
      cursor = page.next_cursor;
    } while (cursor);
    return items;
  }
  async function run(input: Submission, baseline: Job | null) {
    setProgress("Checking website…");
    if (basic) {
      const response = await fetch("/api/basic-reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: input.target_url }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok)
        throw new Error(responseError(response.status, data.detail));
      setSubmission(input);
      setPrevious(baseline);
      setSample(false);
      setJob(data);
      return;
    }
    const created = await request<{ id: string }>("scans", input);
    setSubmission(input);
    setPrevious(baseline);
    setSample(false);
    setChallenge(null);
    setPending(null);
    setJob(null);
    const deadline = Date.now() + 180000;
    while (Date.now() < deadline) {
      const next = await request<Job>("jobs/" + created.id);
      if (!["queued", "running"].includes(next.state)) {
        setJob(next);
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 700));
    }
    throw new Error(
      "The check has not finished. Open Advanced to view its saved progress.",
    );
  }
  async function perform(action: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await action();
    } catch (e) {
      setError(
        "Could not verify. " +
          (e instanceof TypeError
            ? "Check your connection and try again. If the problem continues, explore the sample report."
            : (e as Error).message),
      );
    } finally {
      setBusy(false);
      setProgress("");
    }
  }
  async function start() {
    await perform(async () => {
      let parsed: URL;
      try {
        parsed = new URL(url);
      } catch {
        throw new Error(
          "Enter a valid website URL, including https:// (for example, https://example.com).",
        );
      }
      if (!["http:", "https:"].includes(parsed.protocol))
        throw new Error("Enter an HTTP or HTTPS website URL.");
      const input: Submission = {
        target_url: url,
        session_cookies: [],
        ai: false,
        browser: false,
      };
      if (hosted && !basic) {
        setProgress("Checking domain verification…");
        const projects = await all<Project>("projects");
        // Reuse an existing verified exact hostname, including paginated projects/targets.
        for (const project of projects) {
          const targets = await all<Target>(`projects/${project.id}/targets`);
          const target = targets.find(
            (t) =>
              t.hostname === parsed.hostname &&
              !t.revoked &&
              t.verified_until * 1000 > Date.now(),
          );
          if (target) {
            await run(
              { ...input, project_id: project.id, target_id: target.id },
              null,
            );
            return;
          }
        }
        const project =
          projects[0] ||
          (await request<Project>("projects", { name: "Website checks" }));
        const created = await request<Challenge>(
          `projects/${project.id}/targets`,
          { hostname: parsed.hostname },
        );
        setPending({ ...input, project_id: project.id, target_id: created.id });
        setChallenge(created);
        return;
      }
      await run(input, null);
    });
  }
  function showSample() {
    setJob(sampleJob);
    setPrevious(null);
    setSample(true);
    setSubmission(null);
    setChallenge(null);
    setPending(null);
    setError("");
  }
  return (
    <main id="main-content" className="checker">
      <section className="hero" aria-labelledby="hero-title">
        <div className="hero-label">
          <ShieldCheck size={15} />
          Open-source website security checks
        </div>
        <h1 id="hero-title">
          Understand your website's
          <br className="desktop-break" /> <span>security configuration.</span>
        </h1>
        <p className="hero-description">
          Turn configuration observations into clear next steps.
          <br className="desktop-break" /> Inspect the evidence, make a fix, and
          verify what changed.
        </p>
        <section className="checker-form panel" aria-label="Check a website">
          <form
            noValidate
            onSubmit={(e) => {
              e.preventDefault();
              void start();
            }}
          >
            <label htmlFor="website">Website URL</label>
            <div className="url-row">
              <div className="url-input">
                <GlobeIcon />
                <input
                  id="website"
                  type="url"
                  required
                  maxLength={2048}
                  placeholder="https://your-website.com"
                  autoComplete="url"
                  autoCapitalize="none"
                  spellCheck={false}
                  aria-describedby={
                    error ? "url-help checker-error" : "url-help"
                  }
                  aria-invalid={error.includes("Enter a") && !busy}
                  value={url}
                  disabled={busy}
                  onChange={(e) => {
                    setUrl(e.target.value);
                    setError("");
                  }}
                />
              </div>
              <button className="button" disabled={busy}>
                {busy ? (
                  <LoaderCircle className="spin" size={18} />
                ) : (
                  <Search size={18} />
                )}
                Check website
              </button>
            </div>
          </form>
          <div className="checker-help">
            <p id="url-help">
              <LockKeyhole size={13} />
              Only check websites you own or have permission to test.
            </p>
            <button
              className="text-button"
              disabled={busy}
              onClick={showSample}
            >
              <FlaskConical size={15} />
              Try sample report
            </button>
          </div>
          {hosted && !basic && (
            <p className="auth-note">
              Live checks require sign-in and verification of the exact domain.{" "}
              <a href="/oauth2/sign_in?rd=/">Sign in</a>
            </p>
          )}
          {busy && (
            <div className="notice loading-notice" role="status">
              <LoaderCircle className="spin" size={20} />
              <span>
                <strong>{progress || "Preparing check…"}</strong>
                <small>
                  Collecting bounded evidence. This may take a moment.
                </small>
              </span>
            </div>
          )}
          {error && (
            <div id="checker-error" className="notice error" role="alert">
              <CircleAlert size={20} />
              <span>{error}</span>
            </div>
          )}
        </section>
        <div className="hero-facts">
          <span>
            <Check size={14} />
            Evidence, not a score
          </span>
          <span>
            <Check size={14} />
            No crawling or redirects
          </span>
          <span>
            <Check size={14} />
            No AI required
          </span>
        </div>
      </section>
      {challenge && pending && (
        <section className="panel domain-challenge">
          <p className="eyebrow">Domain ownership</p>
          <h2>Verify your domain before checking</h2>
          <p>
            Add this DNS TXT record for{" "}
            <strong>{new URL(pending.target_url).hostname}</strong>, then verify
            it. No website check has run yet.
          </p>
          <dl>
            <dt>TXT record name</dt>
            <dd>
              <code>{challenge.record}</code>
            </dd>
            <dt>TXT record value</dt>
            <dd>
              <code>{challenge.value}</code>
            </dd>
          </dl>
          <p>
            Challenge expires{" "}
            {new Date(challenge.expires_at * 1000).toLocaleString()}. Subdomains
            need their own verification.
          </p>
          <button
            className="button"
            disabled={busy}
            onClick={() =>
              perform(async () => {
                await request(`targets/${challenge.id}/verify`, {});
                await run(pending, null);
              })
            }
          >
            Verify domain and check website
          </button>
        </section>
      )}
      <div ref={reportRef} className="report-anchor">
        {job && (
          <Report
            job={job}
            previous={previous}
            sample={sample}
            busy={busy}
            onRecheck={() => {
              if (sample) {
                setPrevious(job);
                setJob({ ...sampleJob });
              } else if (submission) {
                void perform(() => run(submission, job));
              }
            }}
          />
        )}
      </div>
      <section className="how-section" aria-labelledby="how-title">
        <div className="section-intro">
          <p className="eyebrow">A clearer path from finding to fix</p>
          <h2 id="how-title">Small checks. Useful answers.</h2>
          <p>No wall of alerts. Just focused observations you can act on.</p>
        </div>
        <div className="how-grid">
          <article>
            <span className="feature-icon">
              <ScanLine size={23} />
            </span>
            <h3>Check your configuration</h3>
            <p>
              Enter an exact URL. PatchProof checks response headers and reports
              what it can observe.
            </p>
          </article>
          <article>
            <span className="feature-icon">
              <FileSearch size={23} />
            </span>
            <h3>Understand the evidence</h3>
            <p>
              See what passed, what needs attention, and what couldn’t be
              verified—with practical next steps.
            </p>
          </article>
          <article>
            <span className="feature-icon">
              <RotateCw size={23} />
            </span>
            <h3>Verify your fix</h3>
            <p>
              Update your configuration, then check again. Compare results to
              see exactly what changed.
            </p>
          </article>
        </div>
      </section>
      <details className="panel check-scope">
        <summary>What gets checked?</summary>
        <p>
          One bounded HTTP GET to the exact URL, with DNS resolution and normal
          TLS certificate verification. No redirects, crawling, sign-in, or
          response body analysis.
        </p>
        {checks.map((c) => (
          <p key={c.id}>
            <strong>{c.title}.</strong> {c.scope}
          </p>
        ))}
        <p>
          The optional static mixed-content browser check is not run here.
          Configure cookie names, browser checks, and AI in{" "}
          <a href="/advanced">the Advanced workbench</a>. These checks do not
          cover all vulnerabilities.
        </p>
      </details>
      <section className="open-source">
        <div>
          <p className="eyebrow">
            <Terminal size={16} />
            Built in the open
          </p>
          <h2>Security tools should be transparent.</h2>
          <p>
            Read the checks. Inspect the code. Make it better.
            <br />
            PatchProof is open source and built for developers who want to
            understand the evidence.
          </p>
          <div className="open-source-links">
            <a className="button secondary" href={repository}>
              <GitFork size={17} />
              Explore on GitHub
            </a>
            <a
              className="text-button"
              href={`${repository}/blob/main/README.md`}
            >
              Read the documentation
            </a>
          </div>
        </div>
        <div className="source-art" aria-hidden="true">
          <ShieldCheck size={64} strokeWidth={1} />
          <span>inspect. fix. verify.</span>
          <code>open source / evidence first</code>
        </div>
      </section>
    </main>
  );
}
function GlobeIcon() {
  return <ScanLine size={19} aria-hidden="true" />;
}
