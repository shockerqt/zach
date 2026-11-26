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
  board_status?: string;
  required_stages: string[];
  stages_completed: string[];
  current_stage?: string;
  active_attempt_id?: string;
  updated_epoch?: number;
  memory: Obj;
}
export interface TargetFile {
  path: string;
  action: string;
  summary: string;
}
export interface AcceptanceCriterion {
  id: string;
  description: string;
}
export interface ContextPack {
  network?: string;
  weight: string;
  base_sha?: string;
  target_files: TargetFile[];
  forbidden_paths: string[];
  worker_checks: string[];
  gate_checks: string[];
  human_operations: string[];
  verification_commands: string[];
  acceptance_criteria: AcceptanceCriterion[];
}
export interface StageAttempt {
  attempt_id: string;
  task_id: string;
  stage: string;
  model: string;
  effort: string;
  started_epoch: number;
  ended_epoch?: number;
  status: string;
  failure_class?: string;
  summary?: string;
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;
  sha_before?: string;
  sha_after?: string;
  phase: string;
  exit_code?: number;
  exit_code_kind?: string;
  retry_generation: number;
}
export interface AttemptAudit {
  attempt_id: string;
  task_id: string;
  stage: string;
  turn_count: number;
  tool_call_count: number;
  tool_error_count: number;
  edit_compile_fail_loops: number;
  redundant_read_count: number;
  cached_input_tokens?: number;
  reasoning_tokens?: number;
  check_divergence: boolean;
  error_code?: string;
  created_epoch: number;
}
export interface TaskDetail {
  task: Task;
  context_pack: ContextPack;
  attempts: StageAttempt[];
  audits: AttemptAudit[];
  decisions: Decision[];
}
export interface Decision {
  decision_id: string;
  task_id: string;
  kind: string;
  question: string;
  options: string[];
  context_summary: string;
  recommended_option?: number;
  status: string;
  choice?: string;
  note?: string;
  resolved_by?: string;
  resolved_epoch?: number;
  retirement_reason?: string;
  created_seq?: number;
  linked_unverified_delivery?: boolean;
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
    updated_epoch: o.updated_epoch == null ? undefined : integer(o.updated_epoch),
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
    recommended_option:
      o.recommended_option == null ? undefined : integer(o.recommended_option),
    status: o.status == null ? "OPEN" : string(o.status),
    choice: optional(o.choice),
    note: optional(o.note),
    resolved_by: optional(o.resolved_by),
    resolved_epoch:
      o.resolved_epoch == null ? undefined : integer(o.resolved_epoch),
    retirement_reason: optional(o.retirement_reason),
    created_seq: o.created_seq == null ? undefined : integer(o.created_seq),
    linked_unverified_delivery: o.linked_unverified_delivery === true,
  };
}
export function snapshot(v: unknown, requireStatus = false): Snapshot {
  const o = object(v);
  if (!Array.isArray(o.tasks) || !Array.isArray(o.open_decisions))
    throw Error("Snapshot no válido");
  const boardStatuses = o.board_statuses == null ? {} : object(o.board_statuses);
  const result: Snapshot = {
    tasks: o.tasks.map((value) => {
      const parsed = task(value);
      parsed.board_status = Object.hasOwn(boardStatuses, parsed.task_id)
        ? string(boardStatuses[parsed.task_id])
        : undefined;
      return parsed;
    }),
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
  const eventType = string(o.event_type);
  const payload = object(o.payload);
  switch (eventType) {
    case "BOARD_STATUS_OBSERVED":
      string(payload.board_status);
      break;
    case "TASK_STATUS_CHANGED":
      string(payload.status);
      optional(payload.board_status);
      break;
    case "DECISION_RETIRED":
      identity(payload.decision_id);
      string(payload.reason);
      break;
  }
  return {
    seq_id: integer(o.seq_id),
    task_id: identity(o.task_id),
    ts_epoch: integer(o.ts_epoch),
    event_type: eventType,
    payload,
  };
}
export function github(task: Task, kind: "issue" | "pull"): string | undefined {
  const repo = task.github_repo;
  const n = kind === "issue" ? task.issue_number : task.pr_number;
  return repo && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo) && n && n > 0
    ? `https://github.com/${repo}/${kind === "issue" ? "issues" : "pull"}/${n}`
    : undefined;
}

function signedInteger(v: unknown): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v))
    throw Error("Entero no válido");
  return v;
}
function boolean(v: unknown): boolean {
  if (typeof v !== "boolean") throw Error("Booleano no válido");
  return v;
}
function contextPack(v: unknown): ContextPack {
  const o = v == null ? {} : object(v);
  const targetFiles = o.target_files == null ? [] : o.target_files;
  const criteria = o.acceptance_criteria == null ? [] : o.acceptance_criteria;
  if (!Array.isArray(targetFiles) || !Array.isArray(criteria))
    throw Error("ContextPack no válido");
  return {
    network: optional(o.network),
    weight: o.weight == null ? "" : string(o.weight),
    base_sha: optional(o.base_sha),
    target_files: targetFiles.map((item) => {
      const f = object(item);
      return {
        path: string(f.path),
        action: f.action == null ? "" : string(f.action),
        summary: f.summary == null ? "" : string(f.summary),
      };
    }),
    forbidden_paths: o.forbidden_paths == null ? [] : strings(o.forbidden_paths),
    worker_checks: o.worker_checks == null ? [] : strings(o.worker_checks),
    gate_checks: o.gate_checks == null ? [] : strings(o.gate_checks),
    human_operations:
      o.human_operations == null ? [] : strings(o.human_operations),
    verification_commands:
      o.verification_commands == null ? [] : strings(o.verification_commands),
    acceptance_criteria: criteria.map((item) => {
      const c = object(item);
      return {
        id: string(c.id),
        description: c.description == null ? "" : string(c.description),
      };
    }),
  };
}
function stageAttempt(v: unknown): StageAttempt {
  const o = object(v);
  return {
    attempt_id: identity(o.attempt_id),
    task_id: identity(o.task_id),
    stage: string(o.stage),
    model: string(o.model),
    effort: string(o.effort),
    started_epoch: integer(o.started_epoch),
    ended_epoch: o.ended_epoch == null ? undefined : integer(o.ended_epoch),
    status: string(o.status),
    failure_class: optional(o.failure_class),
    summary: optional(o.summary),
    input_tokens: o.input_tokens == null ? undefined : integer(o.input_tokens),
    output_tokens:
      o.output_tokens == null ? undefined : integer(o.output_tokens),
    total_tokens: o.total_tokens == null ? undefined : integer(o.total_tokens),
    sha_before: optional(o.sha_before),
    sha_after: optional(o.sha_after),
    phase: o.phase == null ? "RUNNING" : string(o.phase),
    exit_code: o.exit_code == null ? undefined : signedInteger(o.exit_code),
    exit_code_kind: optional(o.exit_code_kind),
    retry_generation:
      o.retry_generation == null ? 0 : integer(o.retry_generation),
  };
}
function attemptAudit(v: unknown): AttemptAudit {
  const o = object(v);
  return {
    attempt_id: identity(o.attempt_id),
    task_id: identity(o.task_id),
    stage: string(o.stage),
    turn_count: integer(o.turn_count),
    tool_call_count: integer(o.tool_call_count),
    tool_error_count: integer(o.tool_error_count),
    edit_compile_fail_loops: integer(o.edit_compile_fail_loops),
    redundant_read_count: integer(o.redundant_read_count),
    cached_input_tokens:
      o.cached_input_tokens == null
        ? undefined
        : integer(o.cached_input_tokens),
    reasoning_tokens:
      o.reasoning_tokens == null ? undefined : integer(o.reasoning_tokens),
    check_divergence: boolean(o.check_divergence),
    error_code: optional(o.error_code),
    created_epoch: integer(o.created_epoch),
  };
}
export function taskDetail(v: unknown): TaskDetail {
  const o = object(v);
  if (
    !Array.isArray(o.attempts) ||
    !Array.isArray(o.audits) ||
    !Array.isArray(o.decisions)
  ) {
    throw Error("Detalle de tarea no válido");
  }
  const rawTask = object(o.task);
  return {
    task: task(rawTask),
    context_pack: contextPack(rawTask.context_pack),
    attempts: o.attempts.map(stageAttempt),
    audits: o.audits.map(attemptAudit),
    decisions: o.decisions.map((item) => decision(item)),
  };
}

function displayMemory(value: unknown): Obj {
  const m = object(value);
  const result: Obj = {};
  if (m.last_check_failure != null)
    result.last_check_failure = string(m.last_check_failure);
  if (m.approved_plan != null)
    result.approved_plan = string(m.approved_plan);
  if (Array.isArray(m.decisions_log))
    result.decisions_log = strings(m.decisions_log);
  if (m.merge_checkpoint != null) {
    const c = object(m.merge_checkpoint);
    result.merge_checkpoint = { phase: string(c.phase) };
  }
  return result;
}
