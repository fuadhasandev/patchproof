// Isolated visual checks of local/hosted workbenches with explicitly mocked APIs.
import { chromium, expect } from "@playwright/test";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdir } from "node:fs/promises";
import assert from "node:assert/strict";
const origin = "http://localhost:3023";
const id = "a".repeat(32),
  target = "b".repeat(32);
const run = {
  rule_id: "http.csp.present",
  applicability: "evaluated",
  cookie_name: null,
  reason: null,
  coverage: "Enforcing CSP header presence on a successful HTML response.",
  remediation: "Configure Content-Security-Policy.",
  evidence: {
    status_code: 200,
    is_https: true,
    is_html: true,
    csp_present: false,
    hsts_present: true,
    cookies: [],
  },
};
const job = {
  id,
  kind: "scan",
  state: "completed",
  target_url: "https://fixture.example/",
  created_at: 1700000000,
  retry_of: null,
  error: null,
  report: {
    baseline: {
      status: "still_present",
      checks: [{ status: "still_present", run }],
    },
  },
  findings: [
    {
      id: target,
      title: "Missing Content-Security-Policy header",
      category: "configuration",
      suggested_fix:
        "Configure an enforcing Content-Security-Policy header appropriate for your application.",
      run,
      latest_recheck: null,
    },
  ],
};
let server, browser;
async function stop() {
  if (server && server.exitCode === null && server.signalCode === null) {
    const done = once(server, "exit");
    server.kill("SIGTERM");
    await done;
  }
}
try {
  browser = await chromium.launch({
    channel: process.env.PATCHPROOF_BROWSER_CHANNEL || "chrome",
    args: ["--host-resolver-rules=MAP localhost 127.0.0.1"],
  });
  await mkdir("test-results/design", { recursive: true });
  for (const mode of ["local", "hosted"]) {
    const env = {
      ...process.env,
      PATCHPROOF_MODE: mode,
      NEXT_TELEMETRY_DISABLED: "1",
    };
    delete env.VERCEL;
    server = spawn(
      process.execPath,
      [
        "node_modules/next/dist/bin/next",
        "start",
        "--hostname",
        "127.0.0.1",
        "--port",
        "3023",
      ],
      { env, stdio: "ignore" },
    );
    let ready = false;
    for (let i = 0; i < 100; i++) {
      try {
        if ((await fetch(origin)).ok) {
          ready = true;
          break;
        }
      } catch {}
      await new Promise((r) => setTimeout(r, 200));
    }
    assert.ok(ready);
    const page = await browser.newPage({ reducedMotion: "reduce" });
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.route("**/api/**", (route) => {
      const request = route.request(),
        path = new URL(request.url()).pathname.replace(
          /^\/api\/(hosted\/)?/,
          "",
        );
      const reply = (json) => route.fulfill({ json });
      if (path === "capabilities")
        return reply({
          browser: true,
          investigation: true,
          ai_configured: false,
          fixture_origin: null,
          history_ttl_seconds: null,
        });
      if (path === "me") return reply({ id });
      if (path === "projects")
        return reply({
          items: [{ id, name: "Fixture project" }],
          next_cursor: null,
        });
      if (path.endsWith("/targets"))
        return reply({
          items: [
            {
              id: target,
              hostname: "fixture.example",
              verified_until: Date.now() / 1000 + 3600,
              revoked: false,
            },
          ],
          next_cursor: null,
        });
      if (path === "scans" && request.method() === "POST") return reply({ id });
      if (path === "scans" || path.endsWith("/scans"))
        return reply({
          items: [{ ...job, finding_count: 1 }],
          next_cursor: null,
        });
      if (path.startsWith("jobs/")) return reply(job);
      if (path.endsWith("/rechecks"))
        return reply({ items: [], next_cursor: null });
      throw Error("Unexpected mock request " + path);
    });
    for (const [device, width, height] of [
      ["desktop", 1440, 1000],
      ["tablet", 768, 1024],
      ["mobile", 390, 844],
    ])
      for (const theme of ["light", "dark"]) {
        await page.setViewportSize({ width, height });
        await page.emulateMedia({ colorScheme: theme });
        await page.goto(origin + "/advanced");
        if (mode === "local") {
          await expect(
            page.getByText("API connected", { exact: true }),
          ).toBeVisible();
          await page.getByLabel("Target URL").fill("https://fixture.example/");
          await page.getByRole("button", { name: "Run security scan" }).click();
        } else {
          await page.getByLabel("Project", { exact: true }).selectOption(id);
          await page
            .getByRole("button", { name: "Open report", exact: true })
            .click();
        }
        await expect(
          page.getByRole("heading", {
            name: "Missing Content-Security-Policy header",
            exact: true,
          }),
        ).toBeVisible();
        assert.ok(
          await page.evaluate(
            () => document.documentElement.scrollWidth <= innerWidth,
          ),
          `${mode}/${device}/${theme} overflow`,
        );
        await page.screenshot({
          path: `test-results/design/${mode}-${device}-${theme}.png`,
          fullPage: true,
        });
        if (mode === "local") {
          await page
            .getByRole("button", { name: "Scan History", exact: true })
            .click();
          await expect(
            page.getByRole("button", { name: "Open report" }),
          ).toBeVisible();
          assert.ok(
            await page.evaluate(
              () => document.documentElement.scrollWidth <= innerWidth,
            ),
            JSON.stringify({mode,device,theme,overflow:await page.evaluate(()=>[...document.querySelectorAll("body *")].filter(e=>e.getBoundingClientRect().right>innerWidth).map(e=>({tag:e.tagName,cls:e.className,width:e.getBoundingClientRect().width})).slice(0,12))}),
          );
          await page.screenshot({
            path: `test-results/design/history-${device}-${theme}.png`,
            fullPage: true,
          });
        }
      }
    assert.deepEqual(errors, []);
    await page.close();
    await stop();
  }
  console.log(
    "PASS: local reports/history and authenticated hosted workbench layouts at desktop/tablet/mobile in light/dark themes (mock APIs).",
  );
} finally {
  if (browser) await browser.close();
  await stop();
}
