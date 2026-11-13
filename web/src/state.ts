import {
  decision,
  object,
  integer,
  string,
  type Decision,
  type Event,
  type Snapshot,
  type Task,
} from "./protocol";
export interface Stage {
  attempt: string;
  started?: number;
  duration?: number;
  model?: string;
  status: string;
}
export interface State {
  tasks: Task[];
  decisions: Decision[];
  cursor: number;
  watermark: number;
  feed: (Event & { detail?: string })[];
  stages: Record<string, Stage>;
  status?: Snapshot["status"];
  mergedUntil: number;
  reset: boolean;
  syncVersion: number;
}
export const initial: State = {
  tasks: [],
  decisions: [],
  cursor: 0,
  watermark: 0,
  feed: [],
  stages: {},
  mergedUntil: 0,
  reset: false,
  syncVersion: 0,
};
export function acceptSnapshot(s: State, v: Snapshot): State {
  const reset = v.as_of_seq < s.cursor;
  return {
    ...s,
    syncVersion: s.syncVersion + 1,
    tasks: v.tasks,
    decisions: v.open_decisions,
    cursor: v.as_of_seq,
    watermark: v.as_of_seq,
    status: v.status ?? s.status,
    ...(reset ? { feed: [], stages: {}, mergedUntil: 0 } : {}),
    reset,
  };
}
export function applyEvent(s: State, e: Event): State {
  if (e.seq_id <= s.cursor) return s;
  let tasks = s.tasks.map((t) => ({ ...t })),
    decisions = [...s.decisions],
    stages = { ...s.stages },
    mergedUntil = s.mergedUntil;
  const p = e.payload;
  let t = tasks.find((t) => t.task_id === e.task_id);
  if (!t) {
    t = {
      task_id: e.task_id,
      title: "Título no disponible",
      repository: "Repositorio no disponible",
      weight: "No disponible",
      status: "Observado en eventos",
      required_stages: [],
      stages_completed: [],
      memory: {},
    };
    tasks.push(t);
  }
  switch (e.event_type) {
    case "DECISION_REQUIRED": {
      const d = decision(p, e.task_id);
      decisions = [
        ...decisions.filter((x) => x.decision_id !== d.decision_id),
        d,
      ];
      break;
    }
    case "DECISION_RESOLVED": {
      const id = string(p.decision_id);
      string(p.choice);
      decisions = decisions.filter((d) => d.decision_id !== id);
      break;
    }
    case "STAGE_STARTED":
    case "STAGE_COMPLETED": {
      const stage = string(p.stage),
        attempt = string(p.attempt_id),
        key = e.task_id + ":" + stage,
        old = stages[key];
      const started =
        e.event_type === "STAGE_STARTED"
          ? e.ts_epoch
          : old?.attempt === attempt
            ? old.started
            : undefined;
      stages[key] = {
        attempt,
        started,
        duration:
          e.event_type === "STAGE_COMPLETED" && started != null
            ? Math.max(0, e.ts_epoch - started)
            : undefined,
        model:
          p.model == null
            ? old?.attempt === attempt
              ? old.model
              : undefined
            : string(p.model),
        status:
          p.status == null
            ? e.event_type === "STAGE_STARTED"
              ? "RUNNING"
              : "Estado no disponible"
            : string(p.status),
      };
      t.current_stage = stage;
      if (e.event_type === "STAGE_STARTED")
        t.stages_completed = t.stages_completed.filter(
          (completed) => completed !== stage,
        );
      if (e.event_type === "STAGE_COMPLETED" && stages[key].status === "PASSED")
        t.stages_completed = [...new Set([...t.stages_completed, stage])];
      break;
    }
    case "WEIGHT_ESCALATED":
      t.weight = string(p.to_weight);
      break;
    case "TASK_DONE":
      t.status = string(p.status);
      break;
    case "MERGE_ENQUEUED":
      t.pr_number = integer(p.pr_number);
      t.memory = { ...t.memory, merge_checkpoint: { phase: "ENQUEUED" } };
      break;
    case "MERGE_FAILED":
      t.memory = { ...t.memory, last_check_failure: "Merge fallido" };
      break;
    case "MERGE_COMPLETED":
      mergedUntil = Date.now() + 4000;
      t.memory = {
        ...t.memory,
        merge_checkpoint: { phase: "Estado no disponible" },
      };
      break;
  }
  return {
    ...s,
    tasks,
    decisions,
    stages,
    cursor: e.seq_id,
    feed: [
      {
        ...e,
        payload: {},
        ...(e.event_type === "DECISION_RESOLVED"
          ? { detail: `Opción ganadora: ${string(p.choice)}` }
          : {}),
      },
      ...s.feed,
    ].slice(0, 200),
    mergedUntil,
  };
}
// Observations classify the view without rewriting the last snapshot's task status.
export function observedStage(s: State, t: Task): Stage | undefined {
  return t.current_stage
    ? s.stages[t.task_id + ":" + t.current_stage]
    : undefined;
}
export function taskLane(s: State, t: Task): "active" | "queued" | "terminal" {
  if (observedStage(s, t)?.status === "RUNNING") return "active";
  const status = t.status.toLowerCase();
  if (["done", "completed", "cancelled"].includes(status)) return "terminal";
  return ["ready", "backlog"].includes(status) ? "queued" : "active";
}
function stageIsActive(s: State, t: Task): boolean {
  const observed = observedStage(s, t);
  return observed
    ? observed.status === "RUNNING"
    : !!t.current_stage && !t.stages_completed.includes(t.current_stage);
}
export type Mood =
  "decision" | "error" | "paused" | "review" | "hunting" | "merged" | "idle";
export const layers: Record<Mood, string[]> = {
  idle: ["eyes-nap"],
  hunting: ["eyes-wide"],
  review: ["eyes-open", "monocle"],
  decision: ["eyes-open", "badge-decision"],
  merged: ["eyes-happy"],
  error: ["eyes-narrow"],
  paused: ["eyes-nap", "badge-paused"],
};
export function mood(s: State, paused = false, now = Date.now()): Mood {
  if (s.decisions.length) return "decision";
  if (
    s.tasks.some(
      (t) =>
        t.memory.last_check_failure || /FAIL|BLOCKED|ERROR/i.test(t.status),
    ) ||
    Object.values(s.stages).some((x) => /FAIL|ERROR/.test(x.status))
  )
    return "error";
  if (paused) return "paused";
  if (
    s.tasks.some(
      (t) => /review/.test(t.current_stage ?? "") && stageIsActive(s, t),
    )
  )
    return "review";
  if (
    s.tasks.some(
      (t) =>
        ["plan", "impl"].includes(t.current_stage ?? "") && stageIsActive(s, t),
    )
  )
    return "hunting";
  return s.mergedUntil > now ? "merged" : "idle";
}
