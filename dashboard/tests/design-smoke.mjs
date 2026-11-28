// Presentation/state regression checks. Report responses here are explicitly mocked;
// checker-smoke.mjs and basic-smoke.mjs exercise the real controlled backend flows.
import { chromium, expect } from "@playwright/test";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdir } from "node:fs/promises";
import assert from "node:assert/strict";
const origin = "http://localhost:3021";
const server = spawn(
  process.execPath,
  [
    "node_modules/next/dist/bin/next",
    "start",
    "--hostname",
    "127.0.0.1",
    "--port",
    "3021",
  ],
  {
    env: {
      ...process.env,
      VERCEL: "1",
      PATCHPROOF_MODE: "local",
      PATCHPROOF_BASIC_BACKEND_URL: "http://127.0.0.1:1",
      NEXT_TELEMETRY_DISABLED: "1",
    },
    stdio: "ignore",
  },
);
let browser;
try {
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
  assert.ok(ready, "Design preview server did not start");
  browser = await chromium.launch({
    channel: process.env.PATCHPROOF_BROWSER_CHANNEL || "chrome",
    args: ["--host-resolver-rules=MAP localhost 127.0.0.1"],
  });
  const page = await browser.newPage({ reducedMotion: "reduce" });
  const errors = [],
    apiRequests = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("request", (r) => {
    if (new URL(r.url()).pathname.startsWith("/api/"))
      apiRequests.push(r.url());
  });
  await mkdir("test-results/design", { recursive: true });
  for (const [device, width, height] of [
    ["desktop", 1440, 1000],
    ["tablet", 768, 1024],
    ["mobile", 390, 844],
  ]) {
    await page.setViewportSize({ width, height });
    for (const theme of ["light", "dark"]) {
      await page.emulateMedia({ colorScheme: theme });
      await page.goto(origin);
      await page.evaluate(() => localStorage.removeItem("patchproof-theme"));
      await page.reload();
      await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
      const submit = page.getByRole("button", {
        name: "Check website",
        exact: true,
      });
      assert.ok(
        (await submit.boundingBox()).y + (await submit.boundingBox()).height <
          height,
        "Checker must be above fold",
      );
      assert.ok(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
        `${device}/${theme} homepage overflow`,
      );
      await page.screenshot({
        path: `test-results/design/${device}-${theme}-home.png`,
        fullPage: true,
      });
      await page.getByRole("button", { name: "Try sample report" }).click();
      await expect(
        page.getByRole("region", {
          name: "Website security configuration report",
        }),
      ).toBeVisible();
      assert.ok(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
        `${device}/${theme} sample overflow`,
      );
      await page.screenshot({
        path: `test-results/design/${device}-${theme}-sample.png`,
        fullPage: true,
      });
      await expect(
        page.getByText("http.csp.present", { exact: true }),
      ).not.toBeVisible();
      await page
        .locator(".check-card")
        .first()
        .getByText("Technical details & exact check")
        .click();
      await expect(
        page.getByText("http.csp.present", { exact: true }),
      ).toBeVisible();
      await page
        .getByRole("button", { name: "Check again", exact: true })
        .click();
      await expect(
        page.getByRole("heading", { name: "What changed" }),
      ).toBeVisible();
      await page.goto(origin + "/advanced");
      await expect(
        page.getByRole("heading", {
          name: "Go deeper with your own workspace.",
        }),
      ).toBeVisible();
      assert.ok(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
        `${device}/${theme} advanced overflow`,
      );
      await page.screenshot({
        path: `test-results/design/${device}-${theme}-advanced.png`,
        fullPage: true,
      });
    }
  }
  assert.equal(
    apiRequests.length,
    0,
    "Sample and Vercel availability must not request local/hosted APIs",
  );
  await page.goto(origin);
  await page.getByRole("button", { name: "Open navigation" }).click();
  await expect(
    page.getByRole("link", { name: "Advanced", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Close navigation" }).click();
  await page.getByRole("button", { name: "Switch to light theme" }).click();
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.getByLabel("Website URL").fill("not-a-url");
  await page
    .getByRole("button", { name: "Check website", exact: true })
    .click();
  await expect(page.locator(".notice[role=alert]")).toContainText(
    "Enter a valid website URL",
  );
  assert.equal(apiRequests.length, 0);
  for (const [status, message] of [
    [429, "Request limit reached"],
    [503, "service is unavailable"],
  ]) {
    await page.route("**/api/basic-reports", (route) =>
      route.fulfill({ status, json: { detail: "Controlled failure" } }),
    );
    await page.getByLabel("Website URL").fill("https://fixture.example/");
    await page
      .getByRole("button", { name: "Check website", exact: true })
      .click();
    await expect(page.locator(".notice[role=alert]")).toContainText(message);
    await page.screenshot({
      path: `test-results/design/mobile-error-${status}.png`,
      fullPage: true,
    });
    await page.unroute("**/api/basic-reports");
  }
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  await page.route("**/api/basic-reports", async (route) => {
    await gate;
    await route.fulfill({
      json: {
        id: "partial",
        kind: "scan",
        state: "interrupted",
        target_url: "https://fixture.example/",
        created_at: Date.now() / 1000,
        findings: [],
        report: { baseline: { checks: [] } },
        error: null,
      },
    });
  });
  await page
    .getByRole("button", { name: "Check website", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("Checking website");
  await expect(
    page.getByRole("button", { name: "Check website", exact: true }),
  ).toBeDisabled();
  await page.screenshot({
    path: "test-results/design/mobile-loading.png",
    fullPage: true,
  });
  release();
  await expect(page.getByRole("status")).toContainText("Partial results");
  await expect(
    page.locator(".check-card .badge").filter({ hasText: "Could not verify" }),
  ).toHaveCount(3);
  await page.screenshot({
    path: "test-results/design/mobile-partial.png",
    fullPage: true,
  });
  assert.deepEqual(errors, []);
  console.log(
    "PASS: desktop/tablet/mobile × light/dark; above-fold checker; sample/no API traffic; technical details; comparison; Vercel availability/no local access; theme persistence; mobile navigation; invalid URL, 429, 503, loading and partial-result states.",
  );
} finally {
  if (browser) await browser.close();
  if (server.exitCode === null && server.signalCode === null) {
    const ended = once(server, "exit");
    server.kill("SIGTERM");
    await ended;
  }
}
