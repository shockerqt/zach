import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
const task = {
  task_id: "ZACH-030",
  title: "Build the approved Zach control panel",
  repository: "zach",
  github_repo: "shockerqt/zach",
  issue_number: 63,
  pr_number: 90,
  weight: "L",
  status: "In Progress",
  required_stages: ["plan", "plan-review", "impl", "pr-review"],
  stages_completed: ["plan", "plan-review"],
  current_stage: "impl",
  memory: {},
};
const decision = {
  decision_id: "decision-1",
  task_id: "ZACH-030",
  kind: "plan_approval",
  question: "¿Aprobar el plan de ZACH-030?",
  options: ["Approve", "Request Changes", "Reject"],
  context_summary:
    "Panel de control revisado. Hace falta tu aprobación para continuar.",
  status: "OPEN",
};
const data = {
  tasks: [
    task,
    {
      ...task,
      task_id: "INF-020",
      title: "Expose the approved gateway",
      status: "Blocked",
      memory: {
        last_check_failure: "merge failure",
        merge_checkpoint: { phase: "Blocked" },
      },
    },
    {
      ...task,
      task_id: "ZACH-031",
      title: "Next task",
      status: "Ready",
      current_stage: null,
      memory: {},
    },
  ],
  open_decisions: [decision],
  as_of_seq: 10,
  status: {
    heartbeat_epoch: Math.floor(Date.now() / 1000) - 4,
    running_task_slots: 1,
    max_parallel_tasks: 2,
  },
};
async function fixture(
  page: Page,
  opts: {
    empty?: boolean;
    post?: number;
    unknown?: boolean;
    replay?: boolean;
  } = {},
) {
  let snapshots = 0,
    posts = 0;
  const cursors: string[] = [],
    requests: { url: string; authorization: string | undefined }[] = [];
  const base = opts.empty ? { ...data, tasks: [], open_decisions: [] } : data;
  await page.route("**/api/**", async (route) => {
    const req = route.request();
    requests.push({
      url: req.url(),
      authorization: req.headers().authorization,
    });
    if (req.url().endsWith("/snapshot")) {
      snapshots++;
      await route.fulfill({ json: base });
    } else if (req.url().endsWith("/events")) {
      cursors.push(req.headers()["last-event-id"]);
      const e = {
        seq_id: 11,
        task_id: task.task_id,
        task_group: "test",
        ts_epoch: 100,
        event_type: "FUTURE_EVENT",
        payload: {},
      };
      await route.fulfill({
        contentType: "text/event-stream",
        body: `event: snapshot\ndata: ${JSON.stringify({ ...base, status: undefined, as_of_seq: cursors.length === 1 ? 10 : 11 })}\n\nid: 11\nevent: task_event\ndata: ${JSON.stringify(e)}\n\n`,
      });
    } else {
      posts++;
      await new Promise((r) => setTimeout(r, 200));
      await route.fulfill(
        opts.post
          ? { status: opts.post, json: { error: "policy" } }
          : {
              json: {
                outcome: "ALREADY_RESOLVED",
                decision: { ...decision, status: "RESOLVED", choice: "Reject" },
              },
            },
      );
    }
  });
  return { snapshots: () => snapshots, posts: () => posts, cursors, requests };
}
async function connect(page: Page) {
  await page.goto("/");
  await page.getByLabel("Credencial de sesión").fill("fixture-bearer-only");
  await page.getByRole("button", { name: "Conectar", exact: true }).click();
  await expect(page.getByLabel("Credencial de sesión")).toHaveValue("");
}
test("one bootstrap, reconnect cursor, no storage or URL credentials; disconnect aborts retries", async ({
  page,
}) => {
  const consoleMessages: string[] = [];
  page.on("console", (message) => consoleMessages.push(message.text()));
  await page.context().addCookies([
    {
      name: "CF_Authorization",
      value: "synthetic-access-cookie",
      domain: "127.0.0.1",
      path: "/",
      httpOnly: true,
      sameSite: "Lax",
    },
  ]);
  const f = await fixture(page);
  const request = page.waitForRequest((r) => r.url().endsWith("/snapshot"));
  await connect(page);
  expect((await request).headers().cookie).toContain(
    "CF_Authorization=synthetic-access-cookie",
  );
  expect(consoleMessages.join(" ")).not.toContain("fixture-bearer-only");
  expect(await page.evaluate(() => document.cookie)).not.toContain(
    "CF_Authorization",
  );
  await expect(page.getByText("FUTURE_EVENT", { exact: true })).toBeVisible();
  await expect.poll(() => f.cursors.length).toBeGreaterThan(1);
  expect(f.cursors.slice(0, 2)).toEqual(["10", "11"]);
  expect(f.snapshots()).toBe(1);
  expect(
    f.requests.every(
      (r) =>
        r.authorization === "Bearer fixture-bearer-only" &&
        !r.url.includes("fixture-bearer-only"),
    ),
  ).toBe(true);
  expect(
    await page.evaluate(() => [localStorage.length, sessionStorage.length]),
  ).toEqual([0, 0]);
  await page.getByRole("button", { name: "Desconectar", exact: true }).click();
  const count = f.cursors.length;
  await page.waitForTimeout(1600);
  expect(f.cursors.length).toBe(count);
});
test("exact decision choice/note, pending single submission and actual winning response", async ({
  page,
}) => {
  const f = await fixture(page);
  await connect(page);
  const note = page.getByLabel("Nota (opcional)");
  await note.fill("Revisado");
  const sent = page.waitForRequest((r) => r.url().endsWith("/decide"));
  await page
    .getByRole("button", { name: "Aprobar", exact: true })
    .evaluate((button) => {
      (button as HTMLButtonElement).click();
      (button as HTMLButtonElement).click();
    });
  await expect(
    page.getByRole("button", { name: "Rechazar", exact: true }),
  ).toBeDisabled();
  expect((await sent).postDataJSON()).toEqual({
    decision_id: "decision-1",
    choice: "Approve",
    note: "Revisado",
  });
  await expect(
    page.getByText("Ya resuelta · opción ganadora: Reject"),
  ).toBeVisible();
  expect(f.posts()).toBe(1);
});
test("policy denial and unknown outcome are honest and never automatically retried", async ({
  page,
}) => {
  const f = await fixture(page, { post: 503 });
  await connect(page);
  await page.getByRole("button", { name: "Aprobar", exact: true }).click();
  await expect(page.getByText(/Resultado desconocido/)).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Aprobar", exact: true }),
  ).toBeDisabled();
  expect(f.posts()).toBe(1);
});
test("403 explains server capability policy", async ({ page }) => {
  await fixture(page, { post: 403 });
  await connect(page);
  await page.getByRole("button", { name: "Aprobar", exact: true }).click();
  await expect(
    page.getByText(/La política del servidor no permite/),
  ).toBeVisible();
});
for (const width of [390, 1440])
  test(`accessible reference composition at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1000 });
    await page.emulateMedia({ reducedMotion: "reduce" });
    await fixture(page);
    await connect(page);
    await expect(
      page.getByRole("heading", { name: decision.question }),
    ).toBeVisible();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    if (width === 390)
      expect(
        await page
          .locator("main > section")
          .first()
          .locator(":scope > :first-child")
          .getAttribute("class"),
      ).toContain("decision");
    const failures = await new AxeBuilder({ page }).analyze();
    expect(failures.violations).toEqual([]);
    const short = await page
      .locator("button,input,a:not(.skip)")
      .evaluateAll((els) =>
        els
          .filter((e) => e.getBoundingClientRect().height < 44)
          .map((e) => e.outerHTML),
      );
    expect(short).toEqual([]);
    expect(
      await page
        .locator("[id]")
        .evaluateAll(
          (els) => new Set(els.map((e) => e.id)).size === els.length,
        ),
    ).toBe(true);
    await page.screenshot({
      path: `${process.env.ZACH_SCREENSHOT_DIR ?? "test-results"}/panel-${width}.png`,
      fullPage: true,
    });
  });
test("empty offline view and sound opt-in gesture", async ({ page }) => {
  await fixture(page, { empty: true });
  await connect(page);
  await expect(
    page.getByText("No hay decisiones abiertas en el último estado recibido."),
  ).toBeVisible();
  const sound = page.getByRole("button", {
    name: "Activar sonidos",
    exact: true,
  });
  await expect(sound).toHaveAttribute("aria-pressed", "false");
  await sound.click();
  await expect(
    page.getByRole("button", { name: "Silenciar sonidos", exact: true }),
  ).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", { name: "Desconectar", exact: true }).click();
  await expect(
    page.getByRole("button", { name: "Activar sonidos", exact: true }),
  ).toHaveAttribute("aria-pressed", "false");
  await page.screenshot({
    path: `${process.env.ZACH_SCREENSHOT_DIR ?? "test-results"}/panel-empty-offline.png`,
    fullPage: true,
  });
});

test("long identifiers, keyboard navigation, reduced motion and 200% zoom stay usable", async ({
  page,
}) => {
  await page.setViewportSize({ width: 780, height: 1000 });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await fixture(page);
  await connect(page);
  await page.evaluate(() => {
    document.body.style.zoom = "2";
    const id = document.querySelector(".decision .mono");
    if (id) id.textContent = "ZACH-" + "very-long-task-identifier-".repeat(12);
  });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.getByLabel("Nota (opcional)").focus();
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("button", { name: "Aprobar", exact: true }),
  ).toBeFocused();
  expect(
    await page
      .locator('.mascot [data-layer="eyes-open"]')
      .first()
      .evaluate((e) => getComputedStyle(e).transitionDuration),
  ).toBe("0s");
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("button", { name: "Request Changes", exact: true }),
  ).toBeFocused();
});

test("a Ready task moves into En curso on observed start and stops running after PASSED", async ({
  page,
}) => {
  const ready = {
    ...task,
    status: "Ready",
    current_stage: null,
    stages_completed: ["plan", "plan-review"],
  };
  let subscriptions = 0;
  await page.route("**/api/**", async (route) => {
    if (route.request().url().endsWith("/snapshot"))
      return route.fulfill({
        json: { ...data, tasks: [ready], open_decisions: [] },
      });
    subscriptions++;
    const started = {
      seq_id: 11,
      task_id: task.task_id,
      ts_epoch: 100,
      event_type: "STAGE_STARTED",
      payload: { attempt_id: "observed-a", stage: "impl" },
    };
    const completed = {
      ...started,
      seq_id: 12,
      ts_epoch: 105,
      event_type: "STAGE_COMPLETED",
      payload: { ...started.payload, status: "PASSED" },
    };
    const snapshotTask =
      subscriptions === 1
        ? ready
        : {
            ...ready,
            current_stage: "impl",
            stages_completed:
              subscriptions > 2
                ? [...ready.stages_completed, "impl"]
                : ready.stages_completed,
          };
    const watermark = subscriptions === 1 ? 10 : subscriptions === 2 ? 11 : 12;
    await route.fulfill({
      contentType: "text/event-stream",
      body: `event: snapshot\ndata: ${JSON.stringify({ tasks: [snapshotTask], open_decisions: [], as_of_seq: watermark })}\n\nid: 11\nevent: task_event\ndata: ${JSON.stringify(started)}\n\n${subscriptions > 1 ? `id: 12\nevent: task_event\ndata: ${JSON.stringify(completed)}\n\n` : ""}`,
    });
  });
  await connect(page);
  const tasks = page.getByRole("region", { name: "Tareas", exact: true });
  const active = tasks.locator(":scope > div").first();
  const queued = tasks.locator(":scope > div").nth(1);
  await expect(active.getByText(task.title, { exact: true })).toBeVisible();
  await expect(active.getByText("· Etapa observada: RUNNING")).toBeVisible();
  await expect(
    page.getByRole("img", { name: "Zach está cazando", exact: true }).first(),
  ).toBeVisible();
  await expect(queued.getByText(task.title, { exact: true })).toHaveCount(0);
  await expect(queued.getByText(task.title, { exact: true })).toBeVisible();
  await expect(queued.getByText("· Etapa observada: PASSED")).toBeVisible();
  await expect(active.getByText(task.title, { exact: true })).toHaveCount(0);
  await expect(
    page.getByRole("img", { name: "Zach está de siesta", exact: true }).first(),
  ).toBeVisible();
  await page.screenshot({
    path: `${process.env.ZACH_SCREENSHOT_DIR ?? "test-results"}/panel-observed-completed.png`,
    fullPage: true,
  });
});
