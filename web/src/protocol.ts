export type Obj = Record<string, unknown>;
export function object(v: unknown): Obj {
  if (!v || typeof v !== "object" || Array.isArray(v))
    throw Error("Objeto no válido");
  return v as Obj;
}
export function string(v: unknown): string {
  if (typeof v !== "string" || v.length > 65536) throw Error("Texto no válido");
  return v;
}
export function integer(v: unknown): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0)
    throw Error("Secuencia o número no válido");
  return v;
}
const identity = (v: unknown): string => {
  const text = string(v);
  if (!text.trim() || text.length > 256) throw Error("Identidad no válida");
  return text;
};
const strings = (v: unknown): string[] => {
  if (!Array.isArray(v)) throw Error("Lista no válida");
  return v.map(string);
};
const optional = (v: unknown) => (v == null ? undefined : string(v));
export interface Task {
  task_id: string;
  title: string;
  repository: string;
  github_repo?: string;
  issue_number?: number;
  pr_number?: number;
  weight: string;
  status: string;
  required_stages: string[];
  stages_completed: string[];
  current_stage?: string;
  active_attempt_id?: string;
  memory: Obj;
}
export interface Decision {
  decision_id: string;
  task_id: string;
  kind: string;
  question: string;
  options: string[];
  context_summary: string;
  status: string;
  choice?: string;
}
export interface Snapshot {
  tasks: Task[];
  open_decisions: Decision[];
  as_of_seq: number;
  status?: {
    heartbeat_epoch: number;
    running_task_slots: number;
    max_parallel_tasks: number;
  };
}
export interface Event {
  seq_id: number;
  task_id: string;
  ts_epoch: number;
  event_type: string;
  payload: Obj;
}
export function task(v: unknown): Task {
  const o = object(v);
  return {
    task_id: identity(o.task_id),
    title: string(o.title),
    repository: string(o.repository),
    github_repo: optional(o.github_repo),
    issue_number: o.issue_number == null ? undefined : integer(o.issue_number),
    pr_number: o.pr_number == null ? undefined : integer(o.pr_number),
    weight: string(o.weight),
    status: string(o.status),
    required_stages: strings(o.required_stages),
    stages_completed: strings(o.stages_completed),
    current_stage: optional(o.current_stage),
    active_attempt_id: optional(o.active_attempt_id),
    memory: displayMemory(o.memory),
  };
}
export function decision(v: unknown, eventTask?: string): Decision {
  const o = object(v);
  return {
    decision_id: identity(o.decision_id),
    task_id: eventTask ?? identity(o.task_id),
    kind: string(o.kind),
    question: string(o.question),
    options: strings(o.options),
    context_summary:
      o.context_summary == null
        ? "Contexto no disponible"
        : string(o.context_summary),
    status: o.status == null ? "OPEN" : string(o.status),
    choice: optional(o.choice),
  };
}
export function snapshot(v: unknown, requireStatus = false): Snapshot {
  const o = object(v);
  if (!Array.isArray(o.tasks) || !Array.isArray(o.open_decisions))
    throw Error("Snapshot no válido");
  const result: Snapshot = {
    tasks: o.tasks.map(task),
    open_decisions: o.open_decisions.map((v) => decision(v)),
    as_of_seq: integer(o.as_of_seq),
  };
  if (o.status != null) {
    const s = object(o.status);
    result.status = {
      heartbeat_epoch: integer(s.heartbeat_epoch),
      running_task_slots: integer(s.running_task_slots ?? s.active_units),
      max_parallel_tasks: integer(s.max_parallel_tasks),
    };
  } else if (requireStatus) throw Error("Estado ausente");
  return result;
}
export function event(v: unknown): Event {
  const o = object(v);
  return {
    seq_id: integer(o.seq_id),
    task_id: identity(o.task_id),
    ts_epoch: integer(o.ts_epoch),
    event_type: string(o.event_type),
    payload: object(o.payload),
  };
}
export function github(task: Task, kind: "issue" | "pull"): string | undefined {
  const repo = task.github_repo;
  const n = kind === "issue" ? task.issue_number : task.pr_number;
  return repo && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo) && n && n > 0
    ? `https://github.com/${repo}/${kind === "issue" ? "issues" : "pull"}/${n}`
    : undefined;
}

function displayMemory(value: unknown): Obj {
  const m = object(value);
  const result: Obj = {};
  if (m.last_check_failure != null)
    result.last_check_failure = string(m.last_check_failure);
  if (m.merge_checkpoint != null) {
    const c = object(m.merge_checkpoint);
    result.merge_checkpoint = { phase: string(c.phase) };
  }
  return result;
}
