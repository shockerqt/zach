import { describe, it, expect } from "vitest";
import { SSEParser } from "./sse";
import { snapshot, event, integer, github } from "./protocol";
import {
  initial,
  acceptSnapshot,
  applyEvent,
  mood,
  layers,
  taskLane,
  observedStage,
} from "./state";
export const sampleTask = {
  task_id: "ZACH-030",
  title: "Panel",
  repository: "zach",
  github_repo: "shockerqt/zach",
  issue_number: 63,
  weight: "L",
  status: "In Progress",
  required_stages: ["plan", "impl"],
  stages_completed: ["plan"],
  current_stage: "impl",
  memory: {},
};
export const snap = {
  tasks: [sampleTask],
  open_decisions: [],
  as_of_seq: 10,
  status: { heartbeat_epoch: 1, running_task_slots: 1, max_parallel_tasks: 2 },
};
const ev = (seq: number, type: string, payload: unknown = {}) =>
  event({
    seq_id: seq,
    task_id: "ZACH-030",
    ts_epoch: 100,
    event_type: type,
    payload,
  });
describe("wire and stream", () => {
  it("decodes actual snapshot and rejects unsafe identities/cursors", () => {
    expect(snapshot(snap, true).tasks[0].title).toBe("Panel");
    expect(() =>
      snapshot({ ...snap, tasks: [{ ...sampleTask, task_id: {} }] }),
    ).toThrow();
    expect(() => integer(2 ** 53)).toThrow();
    expect(
      github({ ...sampleTask, github_repo: "evil.com/x?x" }, "issue"),
    ).toBeUndefined();
  });
  it("parses every byte split, BOM UTF8 CRLF CR multiline comments and EOF", () => {
    const frames: unknown[] = [];
    const p = new SSEParser((f) => frames.push(f));
    const b = new TextEncoder().encode(
      "\uFEFF:keepalive\r\nevent: snapshot\rdata: á\r\ndata: b\r\nid: 3\r\n\r\ndata: incomplete",
    );
    for (const byte of b) p.push(new Uint8Array([byte]));
    p.finish();
    expect(frames).toEqual([{ event: "snapshot", data: "á\nb", id: "3" }]);
  });
  it("bounds lines and multiline frames", () => {
    expect(() =>
      new SSEParser(() => {}, 5).push(new TextEncoder().encode("data:123456")),
    ).toThrow();
    expect(() =>
      new SSEParser(() => {}, 15).push(
        new TextEncoder().encode("data: 12345\ndata: 12345\ndata: 12345\n"),
      ),
    ).toThrow();
  });
});
describe("authoritative replay projection", () => {
  it("ignores overlapping decision replay and accepts lower watermark reset", () => {
    let s = acceptSnapshot(initial, snapshot(snap));
    const d = {
      decision_id: "d",
      kind: "plan_approval",
      question: "?",
      options: ["Approve", "Reject"],
    };
    expect(applyEvent(s, ev(10, "DECISION_REQUIRED", d))).toBe(s);
    s = applyEvent(s, ev(11, "DECISION_REQUIRED", d));
    expect(s.decisions).toHaveLength(1);
    expect(applyEvent(s, ev(11, "DECISION_REQUIRED", d))).toBe(s);
    s = acceptSnapshot(s, snapshot({ ...snap, as_of_seq: 2 }));
    expect(s.reset).toBe(true);
    expect(s.decisions).toHaveLength(0);
    expect(s.feed).toHaveLength(0);
    expect(s.cursor).toBe(2);
  });
  it("unknown event remains bounded without fabricated task fields and validates before cursor", () => {
    let s = acceptSnapshot(initial, snapshot(snap));
    for (let n = 11; n < 230; n++) s = applyEvent(s, ev(n, "FUTURE_EVENT"));
    expect(s.feed).toHaveLength(200);
    expect(s.tasks[0].status).toBe("In Progress");
    expect(() => applyEvent(s, ev(230, "WEIGHT_ESCALATED", {}))).toThrow();
    expect(s.cursor).toBe(229);
  });
  it("only derives duration from matching observed attempt", () => {
    let s = applyEvent(
      initial,
      ev(1, "STAGE_COMPLETED", {
        attempt_id: "a",
        stage: "impl",
        model: "m",
        status: "FAILED",
      }),
    );
    expect(s.stages["ZACH-030:impl"].duration).toBeUndefined();
    s = applyEvent(
      s,
      ev(2, "STAGE_STARTED", { attempt_id: "b", stage: "impl" }),
    );
    s = applyEvent(
      s,
      ev(3, "STAGE_COMPLETED", {
        attempt_id: "b",
        stage: "impl",
        status: "PASSED",
      }),
    );
    expect(s.stages["ZACH-030:impl"].duration).toBe(0);
  });
  it("selects all exact layer sets with priority", () => {
    const s = acceptSnapshot(initial, snapshot(snap));
    expect(mood(s)).toBe("hunting");
    expect(
      mood({ ...s, tasks: [{ ...s.tasks[0], current_stage: "pr-review" }] }),
    ).toBe("review");
    expect(mood({ ...s, mergedUntil: Date.now() + 5000, tasks: [] })).toBe(
      "merged",
    );
    expect(mood(initial, true)).toBe("paused");
    expect(mood(initial)).toBe("idle");
    const failed = { ...s, tasks: [{ ...s.tasks[0], status: "FAILED" }] };
    expect(mood(failed, true)).toBe("error");
    expect(
      mood(
        {
          ...failed,
          decisions: [
            {
              decision_id: "d",
              task_id: "t",
              kind: "k",
              question: "?",
              options: [],
              context_summary: "",
              status: "OPEN",
            },
          ],
        },
        true,
      ),
    ).toBe("decision");
    expect(layers).toEqual({
      idle: ["eyes-nap"],
      hunting: ["eyes-wide"],
      review: ["eyes-open", "monocle"],
      decision: ["eyes-open", "badge-decision"],
      merged: ["eyes-happy"],
      error: ["eyes-narrow"],
      paused: ["eyes-nap", "badge-paused"],
    });
  });
});

it("classifies observed Ready stage start as active without inventing task status, then stops running on completion", () => {
  let s = acceptSnapshot(
    initial,
    snapshot({
      ...snap,
      tasks: [{ ...sampleTask, status: "Ready", current_stage: null }],
    }),
  );
  expect(taskLane(s, s.tasks[0])).toBe("queued");
  expect(mood(s)).toBe("idle");
  s = applyEvent(
    s,
    ev(11, "STAGE_STARTED", { attempt_id: "a", stage: "impl" }),
  );
  expect(taskLane(s, s.tasks[0])).toBe("active");
  expect(mood(s)).toBe("hunting");
  expect(s.tasks[0].status).toBe("Ready");
  expect(observedStage(s, s.tasks[0])?.status).toBe("RUNNING");
  s = applyEvent(
    s,
    ev(12, "STAGE_COMPLETED", {
      attempt_id: "a",
      stage: "impl",
      status: "PASSED",
    }),
  );
  expect(taskLane(s, s.tasks[0])).toBe("queued");
  expect(mood(s)).toBe("idle");
  expect(observedStage(s, s.tasks[0])?.status).toBe("PASSED");
  s = applyEvent(
    s,
    ev(13, "STAGE_STARTED", { attempt_id: "b", stage: "impl" }),
  );
  expect(s.tasks[0].stages_completed).not.toContain("impl");
  expect(taskLane(s, s.tasks[0])).toBe("active");
  expect(mood(s)).toBe("hunting");
  s = applyEvent(
    s,
    ev(14, "STAGE_COMPLETED", {
      attempt_id: "b",
      stage: "impl",
      status: "FUTURE_STATUS",
    }),
  );
  expect(taskLane(s, s.tasks[0])).toBe("queued");
  expect(mood(s)).toBe("idle");
  expect(observedStage(s, s.tasks[0])?.status).toBe("FUTURE_STATUS");
  expect(s.tasks[0].status).toBe("Ready");
});
