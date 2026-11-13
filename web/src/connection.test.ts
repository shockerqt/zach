import { afterEach, describe, it, expect, vi } from "vitest";
import { Connection } from "./connection";
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
      "d",
      "new-live-decision",
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
