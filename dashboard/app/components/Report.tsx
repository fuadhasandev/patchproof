import {
  CircleCheck,
  CircleHelp,
  TriangleAlert,
  RotateCw,
  Globe,
  Clock3,
  FlaskConical,
  Info,
  ListFilter,
} from "lucide-react";
import { checks, outcome, results } from "@/lib/check-report";
import type { Job, Result } from "@/lib/types";

const groups = ["Needs attention", "Passed", "Could not verify"] as const;
type Outcome = (typeof groups)[number];
export function StatusIcon({ status }: { status: string }) {
  const Icon =
    status === "Passed"
      ? CircleCheck
      : status === "Needs attention"
        ? TriangleAlert
        : CircleHelp;
  return <Icon size={17} aria-hidden="true" />;
}
function statusClass(status: Outcome) {
  return status === "Passed"
    ? "resolved"
    : status === "Needs attention"
      ? "still_present"
      : "unverified";
}
function Evidence({ result, rule }: { result?: Result; rule: string }) {
  const evidence = result?.run.evidence;
  const present =
    rule === "http.csp.present"
      ? evidence?.csp_present
      : evidence?.hsts_present;
  return (
    <div className="observed-evidence">
      <span className="field-label">Observed evidence</span>
      <dl>
        <div>
          <dt>HTTP response</dt>
          <dd>{evidence?.status_code ?? "Unavailable"}</dd>
        </div>
        <div>
          <dt>
            {rule === "http.session-cookie.secure"
              ? "Cookie selection"
              : rule === "http.csp.present"
                ? "CSP header"
                : "HSTS header"}
          </dt>
          <dd>
            {rule === "http.session-cookie.secure"
              ? "None configured"
              : present === true
                ? "Present"
                : present === false
                  ? "Not present"
                  : "Not evaluated"}
          </dd>
        </div>
        <div>
          <dt>Transport</dt>
          <dd>
            {evidence?.is_https === true
              ? "HTTPS"
              : evidence?.is_https === false
                ? "HTTP"
                : "Unknown"}
          </dd>
        </div>
      </dl>
    </div>
  );
}
export function Report({
  job,
  previous,
  sample,
  busy,
  onRecheck,
}: {
  job: Job;
  previous: Job | null;
  sample: boolean;
  busy: boolean;
  onRecheck: () => void;
}) {
  const current = results(job),
    before = results(previous);
  const incomplete =
    job.state !== "completed" ||
    checks.some((c) => !current.find((r) => r.run.rule_id === c.id));
  return (
    <section
      id="report"
      tabIndex={-1}
      aria-label="Website security configuration report"
      className="configuration-report"
    >
      <div className="report-heading">
        <div>
          <p className="eyebrow">
            {sample ? <FlaskConical size={15} /> : <ListFilter size={15} />}{" "}
            {sample ? "Sample report · preloaded example" : "Check report"}
          </p>
          <h2>Website security configuration report</h2>
          <p className="report-url">
            <Globe size={17} />
            <span>{job.target_url}</span>
          </p>
          <p className="report-date">
            <Clock3 size={14} />
            {sample ? (
              "Illustrative data · not a live check"
            ) : (
              <>
                Checked{" "}
                <time dateTime={new Date(job.created_at * 1000).toISOString()}>
                  {new Date(job.created_at * 1000).toLocaleString()}
                </time>
              </>
            )}
          </p>
        </div>
        <button className="button" disabled={busy} onClick={onRecheck}>
          <RotateCw size={17} className={busy ? "spin" : ""} />
          Check again
        </button>
      </div>
      {sample && (
        <p className="notice">
          <FlaskConical size={18} />
          <span>
            <strong>You’re viewing a sample.</strong> Illustrative example data.
            No request is made to example.com. Check again reloads the same
            sample checks; live checks use the URL above.
          </span>
        </p>
      )}
      {incomplete && (
        <p className="notice" role="status">
          <TriangleAlert size={18} />
          <span>
            <strong>Partial results · Could not verify all checks.</strong>{" "}
            {job.state !== "completed"
              ? `The check ${job.state}. ${job.error || ""}`
              : "Some checks returned no evidence."}{" "}
            Available observations are shown below. An incomplete check is not a
            pass.
          </span>
        </p>
      )}
      <div className="summary-strip">
        {groups.map((group) => (
          <div key={group} className={statusClass(group)}>
            <span className="summary-label">
              <StatusIcon status={group} />
              {group}
            </span>
            <strong>
              {
                checks.filter(
                  (c) =>
                    outcome(current.find((r) => r.run.rule_id === c.id)) ===
                    group,
                ).length
              }
              <span>checks</span>
            </strong>
          </div>
        ))}
      </div>
      {previous && (
        <section className="panel changes">
          <div className="section-title">
            <RotateCw size={20} />
            <h3>What changed</h3>
          </div>
          <p className="muted">
            Compared with the previous{" "}
            {sample ? "sample report" : "check of the same URL"}. An unavailable
            result does not prove a fix.
          </p>
          <div className="change-list">
            {checks.map((c) => {
              const a = outcome(before.find((r) => r.run.rule_id === c.id)),
                b = outcome(current.find((r) => r.run.rule_id === c.id));
              return (
                <div key={c.id}>
                  <strong>{c.title}</strong>
                  <span>
                    {a === b ? `No status change — ${b}` : `${a} → ${b}`}
                  </span>
                </div>
              );
            })}
          </div>
        </section>
      )}
      <div className="report-layout">
        <div className="report-findings">
          {groups.map((group) => {
            const items = checks.filter(
              (c) =>
                outcome(current.find((r) => r.run.rule_id === c.id)) === group,
            );
            return (
              <section className="result-group" key={group}>
                <div className="group-heading">
                  <h3>{group}</h3>
                  <span>{items.length}</span>
                </div>
                {!items.length && (
                  <p className="empty-group">No checks in this category.</p>
                )}
                {items.map((c) => {
                  const result = current.find((r) => r.run.rule_id === c.id);
                  return (
                    <article
                      className={`panel check-card ${statusClass(group)}-card`}
                      key={c.id}
                    >
                      <div className="check-card-heading">
                        <h4>{c.title}</h4>
                        <span className={`badge ${statusClass(group)}`}>
                          <StatusIcon status={group} />
                          {group}
                        </span>
                      </div>
                      <p>
                        {group === "Passed"
                          ? c.pass
                          : group === "Needs attention"
                            ? c.fail
                            : result?.run.reason ||
                              "The check did not return enough evidence to evaluate this condition."}
                      </p>
                      <Evidence result={result} rule={c.id} />
                      <div className="suggested-fix">
                        <h5>
                          {group === "Passed"
                            ? "Suggested follow-up"
                            : "Suggested fix"}
                        </h5>
                        <p>
                          {group === "Passed"
                            ? "Keep this header configured and review its settings; presence alone does not establish an effective policy."
                            : group === "Could not verify" &&
                                c.id !== "http.session-cookie.secure"
                              ? "Ensure the exact URL is reachable and returns a successful response. CSP needs an HTML page; HSTS needs HTTPS. Then check again."
                              : c.fix}
                        </p>
                      </div>
                      <details>
                        <summary>Technical details &amp; exact check</summary>
                        <p>{c.scope}</p>
                        <p className="technical-rule">
                          Rule <code>{c.id}</code>
                        </p>
                        {result && (
                          <p>
                            {result.run.applicability === "evaluated"
                              ? "Evaluated"
                              : "Not evaluated"}
                            {result.run.reason ? ` · ${result.run.reason}` : ""}
                          </p>
                        )}
                      </details>
                    </article>
                  );
                })}
              </section>
            );
          })}
        </div>
        <aside className="report-aside">
          <section className="panel">
            <Info size={21} />
            <h3>What was checked</h3>
            <p>
              The exact page’s CSP and HSTS response headers. Cookie checks
              require explicitly selected names and could not be evaluated here.
            </p>
            <p>Browser checks and AI were not run.</p>
            <hr />
            <p>
              These are configuration observations,{" "}
              <strong>not an overall security rating.</strong>
            </p>
          </section>
          <div className="aside-note">
            <h4>Make a change. Verify it.</h4>
            <p>
              After updating your configuration, use Check again to compare the
              same URL with this report.
            </p>
            <a href="/advanced">Explore the Advanced workbench</a>
          </div>
        </aside>
      </div>
    </section>
  );
}
