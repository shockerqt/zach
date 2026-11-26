import { describe, it, expect } from "vitest";
import { SSEParser } from "./sse";
import { snapshot, event, integer, github, decision, task, taskDetail } from "./protocol";
import {
  initial,
  acceptSnapshot,
  applyEvent,
  mood,
  layers,
  taskLane,
  taskDecision,
  observedStage,
  sortTasksNewestFirst,
  matchesTaskFilter,
  filterEvents,
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
  it.each(["RUNNING", "FAILED"])(
    "reconciles an observed %s stage completed during disconnection before ignoring replay",
    (previousStatus) => {
      for (const status of ["Ready", "Done"]) {
        let s = acceptSnapshot(initial, snapshot(snap));
        s = applyEvent(
          s,
          ev(11, previousStatus === "RUNNING" ? "STAGE_STARTED" : "STAGE_COMPLETED", {
            attempt_id: "before-disconnect",
            stage: "impl",
            status: previousStatus,
          }),
        );
        expect(mood(s)).toBe(previousStatus === "RUNNING" ? "hunting" : "error");
        s = acceptSnapshot(s, snapshot({
          ...snap,
          tasks: [{ ...sampleTask, status, stages_completed: ["plan", "impl"] }],
          as_of_seq: 12,
        }));
        const reconciled = s;
        s = applyEvent(s, ev(12, "STAGE_COMPLETED", {
          attempt_id: "before-disconnect", stage: "impl", status: "PASSED",
        }));
        expect(s.tasks).toBe(reconciled.tasks);
        expect(s.feed[0].seq_id).toBe(12);
        expect(observedStage(s, s.tasks[0])).toBeUndefined();
        expect(taskLane(s, s.tasks[0])).toBe(status === "Done" ? "terminal" : "queued");
        expect(mood(s)).toBe("idle");
      }
    },
  );
  it("ignores overlapping decision replay and accepts lower watermark reset", () => {
    let s = acceptSnapshot(initial, snapshot(snap));
    const d = {
      decision_id: "d",
      kind: "plan_approval",
      question: "?",
      options: ["Approve", "Reject"],
    };
    s = applyEvent(s, ev(10, "DECISION_REQUIRED", d));
    expect(s.decisions).toHaveLength(0);
    expect(s.feed.map((entry) => entry.seq_id)).toEqual([10]);
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
  it("prefers the linked delivery gate over a newer decision in snapshots and live events", () => {
    const linked = {
      decision_id: "delivery",
      task_id: sampleTask.task_id,
      kind: "prod_promotion_approval",
      question: "Promote?",
      options: ["Approve", "Reject"],
      linked_unverified_delivery: true,
    };
    const newer = {
      ...linked,
      decision_id: "newer",
      question: "Retry?",
      linked_unverified_delivery: false,
    };
    const fromSnapshot = acceptSnapshot(initial, snapshot({
      ...snap,
      open_decisions: [linked, newer],
    }));
    expect(taskDecision(fromSnapshot, fromSnapshot.tasks[0])?.decision_id).toBe("delivery");
    let live = acceptSnapshot(initial, snapshot(snap));
    live = applyEvent(live, ev(11, "DECISION_REQUIRED", linked));
    live = applyEvent(live, ev(12, "DECISION_REQUIRED", newer));
    expect(taskDecision(live, live.tasks[0])?.decision_id).toBe("delivery");
    live = applyEvent(live, ev(13, "DECISION_RESOLVED", {
      decision_id: linked.decision_id, choice: "Approve",
    }));
    expect(taskDecision(live, live.tasks[0])?.decision_id).toBe("newer");
  });
  it("keeps board and effective status independent through live retirement and replay", () => {
    const d = {
      decision_id: "d",
      task_id: sampleTask.task_id,
      kind: "plan_approval",
      question: "?",
      options: ["Approve", "Reject"],
    };
    expect(snapshot(snap).tasks[0].board_status).toBeUndefined();
    let s = acceptSnapshot(initial, snapshot({
      ...snap,
      tasks: [{ ...sampleTask, status: "Blocked" }],
      board_statuses: { [sampleTask.task_id]: "Backlog" },
      open_decisions: [d],
    }));
    expect(s.tasks[0]).toMatchObject({ status: "Blocked", board_status: "Backlog" });
    expect(s.decisions[0].decision_id).toBe("d");
    const observed = ev(11, "BOARD_STATUS_OBSERVED", { board_status: "Cancelled" });
    const terminal = ev(12, "TASK_STATUS_CHANGED", { status: "Cancelled", board_status: "Cancelled" });
    const retired = ev(13, "DECISION_RETIRED", { decision_id: "d", reason: "Cancelled" });
    s = applyEvent(s, observed);
    expect(s.tasks[0]).toMatchObject({ status: "Blocked", board_status: "Cancelled" });
    s = applyEvent(applyEvent(s, terminal), retired);
    expect(s.tasks[0]).toMatchObject({ status: "Cancelled", board_status: "Cancelled" });
    expect(s.decisions).toEqual([]);
    let reconnected = acceptSnapshot(initial, snapshot({
      ...snap,
      tasks: [{ ...sampleTask, status: "Cancelled" }],
      board_statuses: { [sampleTask.task_id]: "Cancelled" },
      as_of_seq: 13,
    }));
    for (const event of [ev(9, "DECISION_REQUIRED", d), observed, terminal, retired, retired])
      reconnected = applyEvent(reconnected, event);
    expect(reconnected.decisions).toEqual([]);
    expect(reconnected.tasks).toEqual(s.tasks);
    expect(reconnected.feed.map((entry) => entry.seq_id)).toEqual([13, 12, 11, 9]);
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

describe("newest-first ordering", () => {
  it("orders snapshot decisions by created_seq descending and prepends live DECISION_REQUIRED events", () => {
    const makeDecision = (id: string, createdSeq: number) => ({
      decision_id: id,
      task_id: sampleTask.task_id,
      kind: "plan_approval",
      question: `Question ${id}?`,
      options: ["Approve", "Reject"],
      created_seq: createdSeq,
    });
    let s = acceptSnapshot(
      initial,
      snapshot({
        ...snap,
        open_decisions: [
          makeDecision("d-old", 5),
          makeDecision("d-mid", 8),
          makeDecision("d-new", 10),
        ],
      }),
    );
    expect(s.decisions.map((d) => d.decision_id)).toEqual([
      "d-new",
      "d-mid",
      "d-old",
    ]);

    s = applyEvent(
      s,
      ev(11, "DECISION_REQUIRED", {
        decision_id: "d-live-1",
        kind: "plan_approval",
        question: "Live 1?",
        options: ["Approve", "Reject"],
      }),
    );
    s = applyEvent(
      s,
      ev(12, "DECISION_REQUIRED", {
        decision_id: "d-live-2",
        kind: "plan_approval",
        question: "Live 2?",
        options: ["Approve", "Reject"],
      }),
    );
    expect(s.decisions.map((d) => d.decision_id)).toEqual([
      "d-live-2",
      "d-live-1",
      "d-new",
      "d-mid",
      "d-old",
    ]);
    expect(taskDecision(s, s.tasks[0])?.decision_id).toBe("d-live-2");
  });

  it("orders active and queued tasks by updated_epoch descending with deterministic task_id tie-breaker", () => {
    const parsed = snapshot({
      ...snap,
      tasks: [
        { ...sampleTask, task_id: "ZACH-002", status: "In Progress", updated_epoch: 100 },
        { ...sampleTask, task_id: "ZACH-001", status: "In Progress", updated_epoch: 100 },
        { ...sampleTask, task_id: "ZACH-003", status: "In Progress", updated_epoch: 250 },
        { ...sampleTask, task_id: "ZACH-010", status: "Ready", current_stage: null, updated_epoch: 50 },
        { ...sampleTask, task_id: "ZACH-011", status: "Ready", current_stage: null, updated_epoch: 300 },
      ],
    });
    const s = acceptSnapshot(initial, parsed);
    const active = sortTasksNewestFirst(
      s.tasks.filter((t) => taskLane(s, t) === "active"),
    );
    const queued = sortTasksNewestFirst(
      s.tasks.filter((t) => taskLane(s, t) === "queued"),
    );
    expect(active.map((t) => t.task_id)).toEqual([
      "ZACH-003",
      "ZACH-001",
      "ZACH-002",
    ]);
    expect(queued.map((t) => t.task_id)).toEqual(["ZACH-011", "ZACH-010"]);
  });
});

describe("compact UI filters", () => {
  it("filters tasks by query and repository and filters events by kind and query", () => {
    const t1 = { ...sampleTask, task_id: "ZACH-085", repository: "zach", title: "Compact UI" };
    const t2 = { ...sampleTask, task_id: "BAL-053", repository: "balance", title: "Meal days" };
    expect(matchesTaskFilter(t1, "", "all")).toBe(true);
    expect(matchesTaskFilter(t1, "compact", "zach")).toBe(true);
    expect(matchesTaskFilter(t1, "compact", "balance")).toBe(false);
    expect(matchesTaskFilter(t2, "meal", "all")).toBe(true);
    expect(matchesTaskFilter(t2, "compact", "all")).toBe(false);

    const feed = [
      { seq_id: 3, task_id: "ZACH-085", ts_epoch: 100, event_type: "STAGE_STARTED", payload: {}, detail: "impl" },
      { seq_id: 2, task_id: "BAL-053", ts_epoch: 99, event_type: "DECISION_REQUIRED", payload: {} },
      { seq_id: 1, task_id: "INF-024", ts_epoch: 98, event_type: "STAGE_FAILED", payload: {} },
    ];
    expect(filterEvents(feed, "", "ALL")).toHaveLength(3);
    expect(filterEvents(feed, "", "STAGE").map((e) => e.seq_id)).toEqual([3, 1]);
    expect(filterEvents(feed, "", "DECISION").map((e) => e.seq_id)).toEqual([2]);
    expect(filterEvents(feed, "", "ERR").map((e) => e.seq_id)).toEqual([1]);
    expect(filterEvents(feed, "zach-085", "ALL").map((e) => e.seq_id)).toEqual([3]);
  });
});

describe("decision recommended_option and task approved_plan parsing", () => {
  it("parses optional recommended_option as non-negative safe integer", () => {
    const base = {
      decision_id: "d-rec",
      task_id: sampleTask.task_id,
      kind: "merge_approval",
      question: "Merge PR?",
      options: ["Approve", "Reject"],
    };
    expect(decision(base).recommended_option).toBeUndefined();
    expect(decision({ ...base, recommended_option: null }).recommended_option).toBeUndefined();
    expect(decision({ ...base, recommended_option: 0 }).recommended_option).toBe(0);
    expect(decision({ ...base, recommended_option: 1 }).recommended_option).toBe(1);
    expect(() => decision({ ...base, recommended_option: -1 })).toThrow();
    expect(() => decision({ ...base, recommended_option: 1.5 })).toThrow();
    expect(() => decision({ ...base, recommended_option: "0" })).toThrow();
  });

  it("preserves approved_plan string in task memory when present", () => {
    expect(task(sampleTask).memory.approved_plan).toBeUndefined();
    expect(
      task({ ...sampleTask, memory: { approved_plan: null } }).memory.approved_plan,
    ).toBeUndefined();
    expect(
      task({ ...sampleTask, memory: { approved_plan: "Step 1\nStep 2" } }).memory
        .approved_plan,
    ).toBe("Step 1\nStep 2");
    expect(() =>
      task({ ...sampleTask, memory: { approved_plan: 123 } }),
    ).toThrow();
  });
});

describe("taskDetail protocol decoder", () => {
  it("decodes task detail with context_pack, stage attempts, audits, and decisions", () => {
    const parsed = taskDetail({
      task: {
        ...sampleTask,
        context_pack: {
          weight: "M",
          base_sha: "abc123def456",
          network: "offline",
          target_files: [
            { path: "src/v2/store.rs", action: "modify", summary: "Add query" },
          ],
          forbidden_paths: [".github/workflows/**"],
          worker_checks: ["cargo test --locked"],
          gate_checks: ["git diff --check"],
          human_operations: [],
          verification_commands: [],
          acceptance_criteria: [{ id: "AC-1", description: "Query works" }],
        },
      },
      attempts: [
        {
          attempt_id: "att-1",
          task_id: sampleTask.task_id,
          stage: "impl",
          model: "gpt-5.4",
          effort: "medium",
          started_epoch: 100,
          ended_epoch: 120,
          status: "PASSED",
          summary: "Implemented",
          input_tokens: 1000,
          output_tokens: 500,
          total_tokens: 1500,
          phase: "FINISHED",
          exit_code: 0,
          retry_generation: 0,
        },
      ],
      audits: [
        {
          attempt_id: "att-1",
          task_id: sampleTask.task_id,
          stage: "impl",
          turn_count: 4,
          tool_call_count: 9,
          tool_error_count: 1,
          edit_compile_fail_loops: 0,
          redundant_read_count: 2,
          cached_input_tokens: 300,
          reasoning_tokens: 120,
          check_divergence: false,
          created_epoch: 120,
        },
      ],
      decisions: [
        {
          decision_id: "dec-1",
          task_id: sampleTask.task_id,
          kind: "plan_approval",
          question: "Approve?",
          options: ["Approve", "Reject"],
          context_summary: "ctx",
          status: "RESOLVED",
          choice: "Approve",
          resolved_by: "operator",
          note: "lgtm",
        },
      ],
    });
    expect(parsed.task.task_id).toBe("ZACH-030");
    expect(parsed.context_pack.target_files[0].path).toBe("src/v2/store.rs");
    expect(parsed.context_pack.acceptance_criteria[0].id).toBe("AC-1");
    expect(parsed.attempts[0].attempt_id).toBe("att-1");
    expect(parsed.audits[0].turn_count).toBe(4);
    expect(parsed.decisions[0].resolved_by).toBe("operator");
  });

  it("rejects malformed taskDetail payloads", () => {
    expect(() => taskDetail({ task: sampleTask, attempts: "bad", audits: [], decisions: [] })).toThrow();
    expect(() =>
      taskDetail({
        task: sampleTask,
        attempts: [],
        audits: [{ attempt_id: "att-1", task_id: "ZACH-030", stage: "impl", turn_count: -1 }],
        decisions: [],
      }),
    ).toThrow();
  });
});
