import { afterEach, describe, it, expect, vi } from "vitest";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { Connection } from "./connection";
import { ConnectionBar, TaskDetailModal } from "./main";
import { initial } from "./state";
import { task } from "./protocol";
const snap = {
  tasks: [],
  open_decisions: [],
  as_of_seq: 10,
  status: { heartbeat_epoch: 1, running_task_slots: 0, max_parallel_tasks: 2 },
};
const frame = (kind: string, value: unknown, id?: number) =>
  `${id == null ? "" : `id: ${id}\n`}event: ${kind}\ndata: ${JSON.stringify(value)}\n\n`;
const stage = {
  seq_id: 11,
  task_id: "t",
  ts_epoch: 1,
  event_type: "DECISION_REQUIRED",
  payload: {
    decision_id: "d",
    kind: "plan_approval",
    question: "?",
    options: ["Approve", "Reject"],
  },
};
const flush = async () => {
  for (let i = 0; i < 40; i++) await Promise.resolve();
};
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});
describe("generation-owned transport", () => {
  it("uses same-origin cookies/header only, dedups replay, reconnects cursor and sounds only new post-watermark events", async () => {
    vi.useFakeTimers();
    const audio: string[] = [];
    const calls: { url: string; init: RequestInit }[] = [];
    let streams = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init: RequestInit) => {
        calls.push({ url, init });
        if (url.endsWith("snapshot")) return Response.json(snap);
        streams++;
        return new Response(
          frame("snapshot", {
            ...snap,
            status: undefined,
            as_of_seq: streams === 1 ? 10 : streams === 2 ? 11 : 12,
            open_decisions:
              streams === 1
                ? []
                : [
                    { ...stage.payload, task_id: "t", status: "OPEN" },
                    ...(streams > 2
                      ? [
                          {
                            ...stage.payload,
                            decision_id: "new-live-decision",
                            task_id: "t",
                            status: "OPEN",
                          },
                        ]
                      : []),
                  ],
          }) +
            frame("task_event", stage, 11) +
            (streams === 1
              ? ""
              : frame(
                  "task_event",
                  {
                    ...stage,
                    seq_id: 12,
                    payload: {
                      ...stage.payload,
                      decision_id: "new-live-decision",
                    },
                  },
                  12,
                )),
          { headers: { "content-type": "text/event-stream" } },
        );
      }),
    );
    const c = new Connection(
      () => {},
      () => {},
      (kind) => audio.push(kind),
    );
    await c.connect("test-only");
    await flush();
    expect(c.state.decisions).toHaveLength(1);
    expect(audio).toEqual(["DECISION_REQUIRED"]);
    await vi.advanceTimersByTimeAsync(1200);
    await flush();
    expect(streams).toBeGreaterThan(1);
    expect(audio).toEqual(["DECISION_REQUIRED", "DECISION_REQUIRED"]);
    expect(c.state.decisions.map((d) => d.decision_id)).toEqual([
      "new-live-decision",
      "d",
    ]);
    expect(c.state.reset).toBe(false);
    await vi.advanceTimersByTimeAsync(2500);
    await flush();
    expect(streams).toBeGreaterThan(2);
    expect(audio).toEqual(["DECISION_REQUIRED", "DECISION_REQUIRED"]);
    expect(c.state.reset).toBe(false);
    expect(calls.filter((c) => c.url.endsWith("snapshot"))).toHaveLength(1);
    expect(calls[2].init.headers).toMatchObject({ "Last-Event-ID": "11" });
    for (const call of calls) {
      expect(call.init.credentials).toBe("same-origin");
      expect(call.init.redirect).toBe("error");
      expect(call.url.startsWith("/api/")).toBe(true);
      expect(call.init.headers).toMatchObject({
        Authorization: "Bearer test-only",
      });
    }
    c.disconnect();
    const n = calls.length;
    await vi.advanceTimersByTimeAsync(60000);
    expect(calls).toHaveLength(n);
  });
  it("watermark suppresses historical decision/audio; resync reconnects without another REST snapshot", async () => {
    vi.useFakeTimers();
    let count = 0;
    const audio = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.endsWith("snapshot")) return Response.json(snap);
        count++;
        return new Response(
          count === 1
            ? frame("snapshot", { ...snap, status: undefined, as_of_seq: 11 }) +
                frame("task_event", stage, 11) +
                frame("resync_required", {
                  type: "RESYNC_REQUIRED",
                  last_seq_id: 11,
                })
            : frame("snapshot", {
                tasks: [],
                open_decisions: [],
                as_of_seq: 2,
              }),
          { headers: { "content-type": "text/event-stream" } },
        );
      }),
    );
    const c = new Connection(
      () => {},
      () => {},
      audio,
    );
    await c.connect("test");
    await flush();
    expect(c.state.decisions).toHaveLength(0);
    expect(audio).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1200);
    await flush();
    expect(c.state.cursor).toBe(2);
    expect(c.state.reset).toBe(true);
    c.disconnect();
  });
  it("auth failure clears generation and stops; malformed frame halts without advancing cursor", async () => {
    vi.useFakeTimers();
    const notices: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) =>
        url.endsWith("snapshot")
          ? Response.json(snap)
          : new Response("event: task_event\ndata: {bad}\n\n", {
              headers: { "content-type": "text/event-stream" },
            }),
      ),
    );
    const c = new Connection(
      () => {},
      (s) => notices.push(s),
    );
    await c.connect("test");
    await flush();
    expect(c.state.cursor).toBe(10);
    expect(notices.at(-1)).toMatch(/no válido/);
    const calls = vi.mocked(fetch).mock.calls.length;
    await vi.advanceTimersByTimeAsync(60000);
    expect(vi.mocked(fetch).mock.calls).toHaveLength(calls);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("", { status: 401 })),
    );
    await c.connect("test");
    expect(notices.at(-1)).toMatch(/denegado/);
  });
  it("disconnect during initial snapshot prevents stale state and stream", async () => {
    let resolve!: (r: Response) => void;
    const f = vi.fn(
      () =>
        new Promise<Response>((r) => {
          resolve = r;
        }),
    );
    vi.stubGlobal("fetch", f);
    const changed = vi.fn(),
      c = new Connection(changed, () => {});
    const promise = c.connect("secret");
    c.disconnect();
    resolve(Response.json(snap));
    await promise;
    expect(changed).toHaveBeenCalledTimes(1);
    expect(changed.mock.calls[0][0].tasks).toEqual([]);
    expect(f).toHaveBeenCalledTimes(1);
  });
});

it("an aborted generation late 401 cannot disconnect a newer credential", async () => {
  vi.useFakeTimers();
  let first!: (r: Response) => void;
  let count = 0;
  const calls: RequestInit[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      calls.push(init);
      if (url.endsWith("snapshot")) {
        if (++count === 1)
          return new Promise<Response>((r) => {
            first = r;
          });
        return Response.json(snap);
      }
      return new Response(frame("snapshot", { ...snap, status: undefined }), {
        headers: { "content-type": "text/event-stream" },
      });
    }),
  );
  const c = new Connection(
    () => {},
    () => {},
  );
  const older = c.connect("older");
  await c.connect("newer");
  await flush();
  first(new Response("", { status: 401 }));
  await older;
  expect(c.active).toBe(true);
  await vi.advanceTimersByTimeAsync(1200);
  await flush();
  expect(calls.at(-1)?.headers).toMatchObject({
    Authorization: "Bearer newer",
  });
  c.disconnect();
});

it("connectAuto connects without Authorization header on 200 and falls back to none on 401", async () => {
  const modes: string[] = [];
  const notices: string[] = [];
  const calls: { url: string; init: RequestInit }[] = [];
  let allowAccess = true;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      if (!allowAccess) return new Response("", { status: 401 });
      if (url.endsWith("snapshot")) return Response.json(snap);
      if (url.endsWith("decide")) {
        return Response.json({
          outcome: "RESOLVED",
          decision: {
            ...stage.payload,
            task_id: "t",
            status: "RESOLVED",
            choice: "Approve",
          },
        });
      }
      return new Response(frame("snapshot", { ...snap, status: undefined }), {
        headers: { "content-type": "text/event-stream" },
      });
    }),
  );

  const c = new Connection(
    () => {},
    (msg) => notices.push(msg),
    () => {},
    (mode) => modes.push(mode),
  );
  await c.connectAuto();
  await flush();
  expect(c.active).toBe(true);
  expect(c.authMode).toBe("access");
  expect(modes).toEqual(["access"]);

  const res = await c.decide("d", "Approve", "");
  expect(res.resolved?.choice).toBe("Approve");
  for (const call of calls) {
    const headers = call.init.headers as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
    expect(call.init.credentials).toBe("same-origin");
  }

  allowAccess = false;
  await c.connectAuto();
  expect(c.active).toBe(false);
  expect(c.authMode).toBe("none");
  expect(notices.at(-1)).toBe("Desconectado");
  c.disconnect();
});

describe("ConnectionBar in access mode", () => {
  it("hides connection section and buttons when connected", () => {
    const html = renderToStaticMarkup(
      React.createElement(ConnectionBar, {
        authMode: "access",
        connected: true,
        notice: "Conectado · SSE",
        onConnect: () => {},
        onReconnect: () => {},
        onDisconnect: () => {},
      }),
    );
    expect(html).toBe("");
    expect(html).not.toContain("Conexión de sesión");
    expect(html).not.toContain("Reconectar");
    expect(html).not.toContain("Desconectar");
  });

  it("renders only status notice and Reconectar button when disconnected", () => {
    const html = renderToStaticMarkup(
      React.createElement(ConnectionBar, {
        authMode: "access",
        connected: false,
        notice: "Desconectado",
        onConnect: () => {},
        onReconnect: () => {},
        onDisconnect: () => {},
      }),
    );
    expect(html).toContain('aria-label="Conexión de sesión"');
    expect(html).toContain('role="status"');
    expect(html).toContain("Desconectado");
    expect(html).toContain("Reconectar");
    expect(html).not.toContain("Desconectar");
    expect(html).not.toContain("Cloudflare Access");
    expect(html).not.toContain("<input");
  });

  it("triggers onReconnect callback to re-establish access session", async () => {
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        calls.push(url);
        if (url.endsWith("snapshot")) return Response.json(snap);
        return new Response(frame("snapshot", { ...snap, status: undefined }), {
          headers: { "content-type": "text/event-stream" },
        });
      }),
    );
    const c = new Connection(
      () => {},
      () => {},
    );
    const element = React.createElement(ConnectionBar, {
      authMode: "access",
      connected: false,
      notice: "Desconectado",
      onConnect: () => {},
      onReconnect: () => {
        void c.connectAuto();
      },
      onDisconnect: () => {},
    });
    expect(element.props.onReconnect).toBeTypeOf("function");
    element.props.onReconnect();
    await flush();
    expect(c.active).toBe(true);
    expect(c.authMode).toBe("access");
    expect(calls.some((u) => u.endsWith("snapshot"))).toBe(true);
    c.disconnect();
  });
});

describe("Connection.fetchTaskDetail and TaskDetailModal", () => {
  it("fetches /api/tasks/:id for 200, returns null for 404, and respects generation/auth", async () => {
    const detailPayload = {
      task: {
        task_id: "ZACH-090",
        title: "Expose details",
        repository: "zach",
        weight: "M",
        status: "In Progress",
        required_stages: ["plan", "impl"],
        stages_completed: ["plan"],
        current_stage: "impl",
        memory: {},
        context_pack: {
          weight: "M",
          target_files: [{ path: "src/v2/store.rs", action: "modify", summary: "query" }],
          forbidden_paths: [],
          worker_checks: ["cargo test --locked"],
          gate_checks: [],
          human_operations: [],
          verification_commands: [],
          acceptance_criteria: [{ id: "AC-1", description: "Done" }],
        },
      },
      attempts: [],
      audits: [],
      decisions: [
        {
          decision_id: "dec-1",
          task_id: "ZACH-090",
          kind: "plan_approval",
          question: "Approve?",
          options: ["Approve"],
          context_summary: "summary",
          status: "RESOLVED",
          choice: "Approve",
          resolved_by: "op",
        },
      ],
    };

    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.endsWith("snapshot")) return Response.json(snap);
        if (url === "/api/tasks/ZACH-090") return Response.json(detailPayload);
        if (url === "/api/tasks/MISSING-1")
          return new Response(JSON.stringify({ error: "not found" }), {
            status: 404,
            headers: { "content-type": "application/json" },
          });
        return new Response(frame("snapshot", { ...snap, status: undefined }), {
          headers: { "content-type": "text/event-stream" },
        });
      }),
    );

    const c = new Connection(() => {}, () => {});
    await c.connect("token-123");
    const ok = await c.fetchTaskDetail("ZACH-090");
    expect(ok?.task.task_id).toBe("ZACH-090");
    expect(ok?.context_pack.target_files[0].path).toBe("src/v2/store.rs");
    expect(await c.fetchTaskDetail("MISSING-1")).toBeNull();

    const html = renderToStaticMarkup(
      React.createElement(TaskDetailModal, {
        task: task(detailPayload.task),
        state: initial,
        detail: ok,
        detailLoading: false,
        detailError: "",
        now: 1000,
        onClose: () => {},
        onFilterEvents: () => {},
      }),
    );
    expect(html).toContain("Resumen &amp; Context Pack");
    expect(html).toContain("Intentos &amp; Auditoría (0)");
    expect(html).toContain("src/v2/store.rs");
    expect(html).toContain("Historial de decisiones (1)");

    c.disconnect();
    expect(await c.fetchTaskDetail("ZACH-090")).toBeNull();
  });

  it("disconnects on 401 from fetchTaskDetail", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        if (url.endsWith("snapshot")) return Response.json(snap);
        if (url.startsWith("/api/tasks/"))
          return new Response(JSON.stringify({ error: "unauthorized" }), {
            status: 401,
            headers: { "content-type": "application/json" },
          });
        return new Response(frame("snapshot", { ...snap, status: undefined }), {
          headers: { "content-type": "text/event-stream" },
        });
      }),
    );
    const notices: string[] = [];
    const c = new Connection(() => {}, (m) => notices.push(m));
    await c.connect("token-123");
    await expect(c.fetchTaskDetail("ZACH-090")).rejects.toThrow();
    expect(c.active).toBe(false);
    expect(notices.some((n) => n.includes("Acceso denegado"))).toBe(true);
  });

  it("posts to /api/tasks/:id/explain with refresh flag and handles 200/503", async () => {
    const calls: { url: string; method?: string; body?: string }[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        calls.push({
          url,
          method: init?.method,
          body: typeof init?.body === "string" ? init.body : undefined,
        });
        if (url.endsWith("snapshot")) return Response.json(snap);
        if (url === "/api/tasks/ZACH-091/explain") {
          return Response.json({
            task_id: "ZACH-091",
            updated_epoch: 100,
            model: "gemini-decision-1",
            task_goal: "Meta",
            agent_actions: "Acciones",
            failure_diagnosis: "Diagnóstico",
            option_guide: ["Opción 1"],
            created_epoch: 101,
            cached: false,
          });
        }
        return new Response(frame("snapshot", { ...snap, status: undefined }), {
          headers: { "content-type": "text/event-stream" },
        });
      }),
    );
    const c = new Connection(() => {}, () => {});
    await c.connect("token-123");
    const exp = await c.explainTask("ZACH-091", true);
    expect(exp.task_goal).toBe("Meta");
    expect(exp.cached).toBe(false);
    const postCall = calls.find((x) => x.url === "/api/tasks/ZACH-091/explain");
    expect(postCall?.method).toBe("POST");
    expect(postCall?.body).toBe('{"refresh":true}');
    c.disconnect();
  });
});
