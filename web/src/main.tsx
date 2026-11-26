import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { Dialog } from "@base-ui/react/dialog";
import { Popover } from "@base-ui/react/popover";
import { Switch } from "@base-ui/react/switch";
import { Tabs } from "@base-ui/react/tabs";
import { Tooltip } from "@base-ui/react/tooltip";
import "@fontsource/inter/latin-400.css";
import "@fontsource/inter/latin-500.css";
import "@fontsource/inter/latin-600.css";
import "@fontsource/space-grotesk/latin-600.css";
import "@fontsource/space-grotesk/latin-700.css";
import "@fontsource/jetbrains-mono/latin-400.css";
import "./style.css";
import { Connection, type AuthMode } from "./connection";
import {
  initial,
  mood,
  taskLane,
  taskDecision,
  observedStage,
  sortTasksNewestFirst,
  matchesTaskFilter,
  filterEvents,
  type EventFilterKind,
  type State,
} from "./state";
import {
  github,
  type Task,
  type Decision,
  type TaskDetail,
  type TaskExplanation,
  type AttemptAudit,
} from "./protocol";
import { Mascot, moodText } from "./Mascot";
import { Sound } from "./sound";

function formatAge(nowMs: number, epoch?: number): string {
  if (!epoch) return "—";
  const diff = Math.max(0, Math.floor(nowMs / 1000 - epoch));
  if (diff < 60) return `${diff}s`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m`;
  return `${Math.floor(diff / 3600)}h`;
}

function eventTone(eventType: string): string {
  if (/COMPLETED|PASSED|RESOLVED|MERGED/.test(eventType)) return "is-ok";
  if (/FAIL|ERROR|REJECT|DENIED/.test(eventType)) return "is-err";
  if (/DECISION/.test(eventType)) return "is-warn";
  return "";
}

function AiExplanationPanel({
  taskId,
  connection,
}: {
  taskId: string;
  connection: Connection;
}) {
  const [explanation, setExplanation] = useState<TaskExplanation | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function requestExplain(refresh: boolean) {
    if (loading || !connection.active) return;
    setLoading(true);
    setError("");
    try {
      const result = await connection.explainTask(taskId, refresh);
      setExplanation(result);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "No se pudo explicar la tarea",
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="zcp2-ai-box">
      <div className="zcp2-ai-actions">
        <button
          type="button"
          className="zcp2-btn zcp2-btn-ai"
          disabled={loading || !connection.active}
          onClick={() => void requestExplain(Boolean(explanation))}
        >
          {loading
            ? "Analizando con Gemini…"
            : explanation
              ? "↻ Regenerar"
              : "✦ Explicar con IA"}
        </button>
        {explanation && (
          <span className="zcp2-ai-badge zcp2-mono">
            {explanation.cached ? "Caché" : "En vivo"} · {explanation.model}
          </span>
        )}
      </div>
      {error && (
        <p className="zcp2-notice zcp2-ai-error" role="status">
          {error}
        </p>
      )}
      {explanation && (
        <div className="zcp2-ai-panel" aria-label={`Explicación IA de ${taskId}`}>
          <div className="zcp2-ai-grid">
            {explanation.task_goal && (
              <div className="zcp2-ai-section">
                <div className="zcp2-ai-k">1. Qué pide la tarea</div>
                <p>{explanation.task_goal}</p>
              </div>
            )}
            {explanation.agent_actions && (
              <div className="zcp2-ai-section">
                <div className="zcp2-ai-k">2. Qué hicieron los agentes</div>
                <p>{explanation.agent_actions}</p>
              </div>
            )}
            {explanation.failure_diagnosis && (
              <div className="zcp2-ai-section">
                <div className="zcp2-ai-k">3. Diagnóstico</div>
                <p>{explanation.failure_diagnosis}</p>
              </div>
            )}
            {explanation.option_guide.length > 0 && (
              <div className="zcp2-ai-section">
                <div className="zcp2-ai-k">4. Guía de opciones</div>
                <ul className="zcp2-ai-options">
                  {explanation.option_guide.map((opt, idx) => (
                    <li key={idx}>{opt}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function DecisionRow({
  d,
  t,
  connection,
  epoch,
  syncVersion,
}: {
  d: Decision;
  t?: Task;
  connection: Connection;
  epoch: number;
  syncVersion: number;
}) {
  const [note, setNote] = useState(""),
    [pending, setPending] = useState(false),
    [unknown, setUnknown] = useState(false),
    [message, setMessage] = useState("");
  const generation = useRef(0);
  const inFlight = useRef(false);
  const uncertain = useRef(false);
  useEffect(() => {
    generation.current++;
    inFlight.current = false;
    uncertain.current = false;
    setUnknown(false);
    setPending(false);
  }, [epoch]);
  useEffect(() => {
    uncertain.current = false;
    setUnknown(false);
  }, [syncVersion]);
  const issue = t && github(t, "issue");
  const pull = t && github(t, "pull");
  const lastCheckFailure =
    typeof t?.memory.last_check_failure === "string"
      ? t.memory.last_check_failure
      : undefined;
  async function choose(choice: string) {
    if (inFlight.current || uncertain.current || !connection.active) return;
    inFlight.current = true;
    setPending(true);
    const gen = generation.current;
    const result = await connection.decide(d.decision_id, choice, note);
    if (gen !== generation.current) return;
    inFlight.current = false;
    uncertain.current = result.unknown || !!result.resolved;
    setMessage(result.resolved ? "" : result.message);
    setUnknown(result.unknown || !!result.resolved);
    setPending(false);
  }
  const plan = ["plan_approval", "human-plan-approval"].includes(d.kind);
  return (
    <article className="zcp2-dec-row decision" aria-label={`Decisión ${d.decision_id}`}>
      <div className="zcp2-dec-top">
        <span className="zcp2-dec-kind zcp2-mono">{d.kind}</span>
        <span className="zcp2-mono mono" style={{ fontWeight: 700, fontSize: 11 }}>
          {d.task_id} · {t?.weight ?? "Peso no disponible"}
        </span>
        <h2 className="zcp2-dec-q">{d.question}</h2>
        {issue && (
          <a className="zcp2-link" href={issue} target="_blank" rel="noreferrer">
            Issue ↗
          </a>
        )}
        {pull && (
          <a className="zcp2-link" href={pull} target="_blank" rel="noreferrer">
            PR #{t.pr_number} ↗
          </a>
        )}
      </div>
      {d.context_summary && (
        <p className="zcp2-dec-context">{d.context_summary}</p>
      )}
      {(d.kind === "merge_approval" || d.linked_unverified_delivery) && (
        <p className="zcp2-dec-callout" role="note">
          {d.linked_unverified_delivery && (
            <span>Entrega vinculada sin verificar · </span>
          )}
          {d.kind === "merge_approval"
            ? "Política de merge: verifica checks y PR antes de aprobar."
            : "Confirma el estado de la entrega antes de continuar."}
        </p>
      )}
      {lastCheckFailure && (
        <details className="zcp2-details zcp2-details-err">
          <summary>Último fallo de verificación</summary>
          <pre className="zcp2-pre zcp2-mono">{lastCheckFailure}</pre>
        </details>
      )}
      <AiExplanationPanel taskId={d.task_id} connection={connection} />
      <div className="zcp2-dec-footer">
        <label className="zcp2-note-label">
          <span>Nota (opcional)</span>
          <input
            className="zcp2-note-input"
            maxLength={2000}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            disabled={pending || unknown || !connection.active}
          />
        </label>
        <div className="zcp2-dec-actions">
          {d.options.map((choice, i) => {
            const isRecommended =
              typeof d.recommended_option === "number" &&
              d.recommended_option === i;
            return (
              <button
                key={choice}
                type="button"
                className={`zcp2-btn ${isRecommended ? "zcp2-btn-rec is-recommended" : i === 0 ? "zcp2-btn-ok" : choice === "Reject" ? "zcp2-btn-err" : ""}`}
                data-recommended={isRecommended ? "true" : undefined}
                title={isRecommended ? "Opción recomendada" : undefined}
                aria-description={isRecommended ? "Opción recomendada" : undefined}
                disabled={pending || unknown || !connection.active}
                onClick={() => void choose(choice)}
              >
                {isRecommended && <span aria-hidden="true">★ </span>}
                {plan && choice === "Approve"
                  ? "Aprobar"
                  : plan && choice === "Reject"
                    ? "Rechazar"
                    : choice}
              </button>
            );
          })}
        </div>
      </div>
      {message && (
        <p className="zcp2-notice" role="status">
          {message}
        </p>
      )}
    </article>
  );
}

function TaskRow({
  t,
  s,
  now,
  onSelect,
}: {
  t: Task;
  s: State;
  now: number;
  onSelect: (t: Task) => void;
}) {
  const lane = taskLane(s, t);
  const blocked = !!t.memory.last_check_failure || t.status.toLowerCase() === "blocked";
  const dotClass = blocked
    ? "is-blocked"
    : t.memory.merge_checkpoint
      ? "is-merge"
      : lane === "active"
        ? "is-active"
        : lane === "queued"
          ? "is-queued"
          : "is-done";
  const obs = observedStage(s, t);
  return (
    <div
      className="zcp2-task-row"
      role="button"
      tabIndex={0}
      onClick={() => onSelect(t)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect(t);
        }
      }}
    >
      <span className="zcp2-task-id zcp2-mono">
        <span className={`zcp2-status-dot ${dotClass}`} />
        {t.task_id}
      </span>
      <span className="zcp2-repo zcp2-mono">{t.repository}</span>
      <span className="zcp2-weight zcp2-mono">{t.weight}</span>
      <span className="zcp2-task-title" title={t.title}>
        <span>{t.title}</span>
        {obs && (
          <span style={{ color: "var(--z2-muted)", marginLeft: 6, fontSize: 10.5 }}>
            · Etapa observada: {obs.status}
          </span>
        )}
      </span>
      <span className="zcp2-pipeline" aria-label={`Etapas de ${t.task_id}`}>
        {t.required_stages.map((stage) => {
          const st = s.stages[t.task_id + ":" + stage];
          const done = t.stages_completed.includes(stage);
          const fail = st && /FAIL|ERROR/.test(st.status);
          const running = st?.status === "RUNNING" || t.current_stage === stage;
          return (
            <span
              key={stage}
              title={stage}
              className={`zcp2-pip ${done ? "is-done" : fail ? "is-failed" : running ? "is-running" : ""}`}
            />
          );
        })}
      </span>
      <span className="zcp2-age zcp2-mono">{formatAge(now, t.updated_epoch)}</span>
    </div>
  );
}

export function ConnectionBar({
  authMode,
  connected,
  notice,
  inputRef,
  onConnect,
  onReconnect,
  onDisconnect,
}: {
  authMode: AuthMode;
  connected: boolean;
  notice: string;
  inputRef?: React.RefObject<HTMLInputElement | null>;
  onConnect: (token: string) => void;
  onReconnect: () => void;
  onDisconnect: () => void;
}) {
  if (authMode === "access") {
    if (connected) return null;
    return (
      <section aria-label="Conexión de sesión" className="connection">
        <div className="status" role="status">
          {notice}
        </div>
        <button className="zcp2-btn zcp2-btn-ok" type="button" onClick={onReconnect}>
          Reconectar
        </button>
      </section>
    );
  }
  return (
    <form
      aria-label="Conexión de sesión"
      className="connection"
      onSubmit={(e) => {
        e.preventDefault();
        const token = inputRef?.current?.value ?? "";
        if (inputRef?.current) inputRef.current.value = "";
        onConnect(token);
      }}
    >
      <label>
        <span>Credencial de sesión</span>
        <input
          ref={inputRef}
          type="password"
          autoComplete="off"
          name="session-credential"
          required
        />
      </label>
      <button className="zcp2-btn zcp2-btn-ok" type="submit">
        Conectar
      </button>
      <button className="zcp2-btn" type="button" onClick={onDisconnect}>
        Desconectar
      </button>
      <p>Solo en memoria durante la conexión. El campo se borra al conectar.</p>
      <div className="status" role="status">
        {connected ? "● " : ""}
        {notice}
      </div>
    </form>
  );
}

const SPLIT_X_KEY = "zach.panel.leftWidthPx";
const SPLIT_Y_KEY = "zach.panel.decisionsHeightPx";

function readStoredNumber(key: string): number | null {
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return null;
    const num = Number(raw);
    return Number.isFinite(num) && num > 0 ? num : null;
  } catch {
    return null;
  }
}

function writeStoredNumber(key: string, value: number): void {
  try {
    window.localStorage.setItem(key, String(Math.round(value)));
  } catch {
    // ignore storage errors
  }
}

function App() {
  const [s, setS] = useState(initial),
    [notice, setNotice] = useState("Desconectado"),
    [authMode, setAuthMode] = useState<AuthMode>("none"),
    [on, setOn] = useState(false),
    [now, setNow] = useState(Date.now()),
    [epoch, setEpoch] = useState(0),
    [query, setQuery] = useState(""),
    [repoFilter, setRepoFilter] = useState("all"),
    [ultraDense, setUltraDense] = useState(false),
    [activeTab, setActiveTab] = useState<"all" | "active" | "queued">("all"),
    [eventFilter, setEventFilter] = useState<EventFilterKind>("ALL"),
    [selectedTask, setSelectedTask] = useState<Task | null>(null),
    [taskDetail, setTaskDetail] = useState<TaskDetail | null>(null),
    [detailLoading, setDetailLoading] = useState(false),
    [detailError, setDetailError] = useState(""),
    [leftPaneWidth, setLeftPaneWidth] = useState<number | null>(() =>
      typeof window !== "undefined" ? readStoredNumber(SPLIT_X_KEY) : null,
    ),
    [decisionsHeight, setDecisionsHeight] = useState<number | null>(() =>
      typeof window !== "undefined" ? readStoredNumber(SPLIT_Y_KEY) : null,
    );
  const input = useRef<HTMLInputElement>(null),
    sound = useRef(new Sound()),
    connection = useRef<Connection | null>(null),
    gridRef = useRef<HTMLElement>(null),
    leftColRef = useRef<HTMLElement>(null),
    decisionsRef = useRef<HTMLElement>(null);
  if (!connection.current)
    connection.current = new Connection(
      setS,
      (msg) => {
        setNotice(msg);
        if (
          msg.startsWith("Desconectado") ||
          msg.startsWith("Acceso") ||
          msg.includes("no válido")
        ) {
          sound.current.mute();
          setOn(false);
        }
      },
      (kind) => sound.current.play(kind),
      setAuthMode,
    );
  const c = connection.current;
  const selectedTaskId = selectedTask?.task_id;
  useEffect(() => {
    if (!selectedTaskId) {
      setTaskDetail(null);
      setDetailLoading(false);
      setDetailError("");
      return;
    }
    let cancelled = false;
    setTaskDetail(null);
    setDetailError("");
    if (!c.active) {
      setDetailLoading(false);
      return;
    }
    setDetailLoading(true);
    c.fetchTaskDetail(selectedTaskId)
      .then((detail) => {
        if (cancelled) return;
        setTaskDetail(detail);
        setDetailLoading(false);
      })
      .catch((err) => {
        if (cancelled) return;
        setDetailLoading(false);
        setDetailError(
          err instanceof Error && err.message
            ? err.message
            : "No se pudo cargar el detalle",
        );
      });
    return () => {
      cancelled = true;
    };
  }, [selectedTaskId, c]);
  useEffect(() => {
    const boot = setTimeout(() => {
      void c.connectAuto();
    }, 0);
    const timer = setInterval(() => setNow(Date.now()), 1000);
    const hide = () => {
      if (document.hidden) {
        sound.current.mute();
        setOn(false);
      }
    };
    document.addEventListener("visibilitychange", hide);
    return () => {
      clearTimeout(boot);
      clearInterval(timer);
      document.removeEventListener("visibilitychange", hide);
      c.disconnect();
      sound.current.close();
    };
  }, [c]);

  const currentMood = mood(s, false, now);
  const repos = useMemo(
    () => Array.from(new Set(s.tasks.map((t) => t.repository))).sort(),
    [s.tasks],
  );
  const active = useMemo(
    () =>
      sortTasksNewestFirst(
        s.tasks.filter(
          (t) => taskLane(s, t) === "active" && matchesTaskFilter(t, query, repoFilter),
        ),
      ),
    [s, query, repoFilter],
  );
  const queued = useMemo(
    () =>
      sortTasksNewestFirst(
        s.tasks.filter(
          (t) => taskLane(s, t) === "queued" && matchesTaskFilter(t, query, repoFilter),
        ),
      ),
    [s, query, repoFilter],
  );
  const candidates = s.tasks.filter((t) => t.memory.merge_checkpoint);
  const visibleFeed = useMemo(
    () => filterEvents(s.feed, query, eventFilter),
    [s.feed, query, eventFilter],
  );
  const resolvedDecisions = useMemo(
    () => s.feed.filter((e) => e.event_type === "DECISION_RESOLVED").slice(0, 12),
    [s.feed],
  );
  const connected = notice.includes("SSE") || notice.startsWith("Resincronizado");

  function clampDecisionsHeight(next: number): number {
    const colHeight = leftColRef.current?.getBoundingClientRect().height ?? 720;
    const maxH = Math.max(220, Math.round(colHeight - 160));
    return Math.min(maxH, Math.max(120, Math.round(next)));
  }

  function clampLeftWidth(next: number): number {
    const gridWidth = gridRef.current?.getBoundingClientRect().width ?? 1200;
    const maxW = Math.max(360, Math.round(gridWidth - 340));
    return Math.min(maxW, Math.max(320, Math.round(next)));
  }

  function startVerticalResize(e: React.PointerEvent<HTMLDivElement>) {
    e.preventDefault();
    const startY = e.clientY;
    const startH =
      decisionsRef.current?.getBoundingClientRect().height ??
      decisionsHeight ??
      260;
    let latest = clampDecisionsHeight(startH);
    const onMove = (ev: PointerEvent) => {
      latest = clampDecisionsHeight(startH + (ev.clientY - startY));
      setDecisionsHeight(latest);
    };
    const onUp = () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      writeStoredNumber(SPLIT_Y_KEY, latest);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  }

  function onVerticalSplitterKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
    const cur =
      decisionsHeight ??
      Math.round(decisionsRef.current?.getBoundingClientRect().height ?? 260);
    let next: number | null = null;
    if (e.key === "ArrowDown") next = clampDecisionsHeight(cur + 24);
    else if (e.key === "ArrowUp") next = clampDecisionsHeight(cur - 24);
    else if (e.key === "Home") next = 120;
    else if (e.key === "End") next = clampDecisionsHeight(9999);
    if (next !== null) {
      e.preventDefault();
      setDecisionsHeight(next);
      writeStoredNumber(SPLIT_Y_KEY, next);
    }
  }

  function startHorizontalResize(e: React.PointerEvent<HTMLDivElement>) {
    e.preventDefault();
    const startX = e.clientX;
    const startW =
      leftColRef.current?.getBoundingClientRect().width ??
      leftPaneWidth ??
      720;
    let latest = clampLeftWidth(startW);
    const onMove = (ev: PointerEvent) => {
      latest = clampLeftWidth(startW + (ev.clientX - startX));
      setLeftPaneWidth(latest);
    };
    const onUp = () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      writeStoredNumber(SPLIT_X_KEY, latest);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
  }

  function onHorizontalSplitterKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
    const cur =
      leftPaneWidth ??
      Math.round(leftColRef.current?.getBoundingClientRect().width ?? 720);
    let next: number | null = null;
    if (e.key === "ArrowRight") next = clampLeftWidth(cur + 24);
    else if (e.key === "ArrowLeft") next = clampLeftWidth(cur - 24);
    else if (e.key === "Home") next = 320;
    else if (e.key === "End") next = clampLeftWidth(9999);
    if (next !== null) {
      e.preventDefault();
      setLeftPaneWidth(next);
      writeStoredNumber(SPLIT_X_KEY, next);
    }
  }

  return (
    <Tooltip.Provider delay={220}>
      <div className="zcp2-root" data-density={ultraDense ? "ultra" : "compact"}>
        <a className="skip" href="#main">
          Ir al contenido
        </a>
        <header className="zcp2-topbar">
          <div className="zcp2-brand">
            <Mascot mood={currentMood} small />
            <h1 className="zcp2-title">Zach</h1>
            <Tooltip.Root>
              <Tooltip.Trigger
                type="button"
                className={`zcp2-pill ${connected ? "is-live" : ""}`}
              >
                <span className="zcp2-dot" />
                {s.status
                  ? `Latido ${Math.max(0, Math.floor(now / 1000 - s.status.heartbeat_epoch))}s`
                  : "Latido —"}
                {s.status
                  ? ` · ${s.status.running_task_slots}/${s.status.max_parallel_tasks}`
                  : ""}
              </Tooltip.Trigger>
              <Tooltip.Portal>
                <Tooltip.Positioner sideOffset={6}>
                  <Tooltip.Popup className="zcp2-tooltip">
                    {connected
                      ? "Stream SSE conectado al daemon Zach"
                      : "Sin conexión activa al stream SSE"}
                  </Tooltip.Popup>
                </Tooltip.Positioner>
              </Tooltip.Portal>
            </Tooltip.Root>
          </div>

          <div className="zcp2-kpis">
            <button
              type="button"
              className="zcp2-kpi-btn"
              aria-pressed={activeTab === "active"}
              onClick={() => setActiveTab(activeTab === "active" ? "all" : "active")}
            >
              <span>En curso</span>
              <span className="zcp2-kpi-num">{active.length}</span>
            </button>
            <button
              type="button"
              className="zcp2-kpi-btn"
              aria-pressed={activeTab === "queued"}
              onClick={() => setActiveTab(activeTab === "queued" ? "all" : "queued")}
            >
              <span>En cola</span>
              <span className="zcp2-kpi-num">{queued.length}</span>
            </button>
            <span className="zcp2-pill">Merge {candidates.length}</span>
          </div>

          <div className="zcp2-controls">
            <input
              type="search"
              className="zcp2-search zcp2-mono"
              aria-label="Filtrar tareas y eventos"
              placeholder="Filtrar tarea, repo, evento..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <select
              className="zcp2-select"
              aria-label="Filtrar repositorio"
              value={repoFilter}
              onChange={(e) => setRepoFilter(e.target.value)}
            >
              <option value="all">Todos los repos</option>
              {repos.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
            <label className="zcp2-density">
              <span>Ultra-dense</span>
              <Switch.Root
                className="zcp2-switch"
                checked={ultraDense}
                onCheckedChange={setUltraDense}
                aria-label="Ultra-dense"
              >
                <Switch.Thumb className="zcp2-switch-thumb" />
              </Switch.Root>
            </label>
            <button
              type="button"
              className="zcp2-btn"
              aria-pressed={on}
              onClick={async () => {
                await sound.current.toggle();
                setOn(sound.current.enabled);
              }}
            >
              {on ? "Silenciar sonidos" : "Activar sonidos"}
            </button>
          </div>
        </header>

      <ConnectionBar
        authMode={authMode}
        connected={connected}
        notice={notice}
        inputRef={input}
        onConnect={(token) => {
          setEpoch((x) => x + 1);
          sound.current.mute();
          setOn(false);
          void c.connect(token);
        }}
        onReconnect={() => {
          setEpoch((x) => x + 1);
          sound.current.mute();
          setOn(false);
          void c.connectAuto();
        }}
        onDisconnect={() => {
          c.disconnect();
          sound.current.mute();
          setOn(false);
          setEpoch((x) => x + 1);
          if (input.current) input.current.value = "";
        }}
      />

      <main
        id="main"
        ref={gridRef}
        className="zcp2-grid"
        style={
          leftPaneWidth != null
            ? ({ "--z2-left-col": `${leftPaneWidth}px` } as React.CSSProperties)
            : undefined
        }
      >
        {/* Left Pane: Pending Decisions Strip + Tabbed Dense Task Table */}
        <section
          ref={leftColRef}
          className="zcp2-col"
          aria-label="Decisiones pendientes y Tareas"
        >
          <div className="zcp2-sec-head">
            <span className="zcp2-sec-title">
              Decisiones pendientes
              <span className="zcp2-count">{s.decisions.length}</span>
            </span>
            <span className="zcp2-mono" style={{ color: "var(--z2-faint)", fontSize: 10 }}>
              {moodText[currentMood]}
            </span>
          </div>

          <section
            ref={decisionsRef}
            aria-label="Decisiones pendientes"
            className="zcp2-decisions"
            style={
              decisionsHeight != null && s.decisions.length > 0
                ? { height: `${decisionsHeight}px`, maxHeight: "none" }
                : undefined
            }
          >
            {s.decisions.length ? (
              s.decisions.map((d) => (
                <DecisionRow
                  key={d.decision_id}
                  d={d}
                  t={s.tasks.find((t) => t.task_id === d.task_id)}
                  connection={c}
                  epoch={epoch}
                  syncVersion={s.syncVersion}
                />
              ))
            ) : (
              <div style={{ padding: "6px 10px", color: "var(--z2-muted)", fontSize: 11 }}>
                No hay decisiones abiertas en el último estado recibido.
              </div>
            )}
          </section>

          <div
            role="separator"
            tabIndex={0}
            aria-orientation="horizontal"
            aria-label="Redimensionar panel de decisiones y tareas"
            aria-valuenow={decisionsHeight ?? 260}
            aria-valuemin={120}
            aria-valuemax={600}
            className="zcp2-splitter zcp2-splitter-h"
            onPointerDown={startVerticalResize}
            onKeyDown={onVerticalSplitterKeyDown}
          />

          <Tabs.Root
            className="zcp2-tabs-root"
            value={activeTab}
            onValueChange={(val) => setActiveTab(val as "all" | "active" | "queued")}
          >
            <Tabs.List className="zcp2-tabs-list" aria-label="Filtro de tareas">
              <Tabs.Tab className="zcp2-tab" value="all">
                Todas ({active.length + queued.length})
              </Tabs.Tab>
              <Tabs.Tab className="zcp2-tab" value="active">
                En curso ({active.length})
              </Tabs.Tab>
              <Tabs.Tab className="zcp2-tab" value="queued">
                En cola ({queued.length})
              </Tabs.Tab>
            </Tabs.List>

            <Tabs.Panel className="zcp2-tab-panel-wrap" value={activeTab}>
              <section className="zcp2-tab-panel" aria-label="Tareas">
                <div className="zcp2-table-head">
                  <span>Task</span>
                  <span>Repo</span>
                  <span>W</span>
                  <span>Title</span>
                  <span>Stages</span>
                  <span style={{ textAlign: "right" }}>Age</span>
                </div>
                {activeTab !== "queued" && (
                  <div>
                    <h2 className="zcp2-group-label">En curso ({active.length})</h2>
                    {active.length ? (
                      active.map((t) => (
                        <TaskRow key={t.task_id} t={t} s={s} now={now} onSelect={setSelectedTask} />
                      ))
                    ) : (
                      <p style={{ padding: "6px 10px", color: "var(--z2-muted)", margin: 0 }}>
                        No hay tareas en curso en el último estado recibido.
                      </p>
                    )}
                  </div>
                )}
                {activeTab !== "active" && (
                  <div>
                    <h2 className="zcp2-group-label">En cola ({queued.length})</h2>
                    {queued.length ? (
                      queued.map((t) => (
                        <TaskRow key={t.task_id} t={t} s={s} now={now} onSelect={setSelectedTask} />
                      ))
                    ) : (
                      <p style={{ padding: "6px 10px", color: "var(--z2-muted)", margin: 0 }}>
                        No hay tareas en cola en el último estado recibido.
                      </p>
                    )}
                  </div>
                )}
              </section>
            </Tabs.Panel>
          </Tabs.Root>
        </section>

        <div
          role="separator"
          tabIndex={0}
          aria-orientation="vertical"
          aria-label="Redimensionar panel izquierdo y derecho"
          aria-valuenow={leftPaneWidth ?? 720}
          aria-valuemin={320}
          aria-valuemax={1100}
          className="zcp2-splitter zcp2-splitter-v"
          onPointerDown={startHorizontalResize}
          onKeyDown={onHorizontalSplitterKeyDown}
        />

        {/* Right Pane: Merge Queue Strip + Dense Live Event Stream */}
        <aside className="zcp2-col" aria-label="Cola de merge y Eventos">
          <div className="zcp2-sec-head">
            <h2 id="merge-heading" className="zcp2-sec-title">
              Cola de merge
              <span className="zcp2-count">{candidates.length}</span>
            </h2>
            <Popover.Root>
              <Popover.Trigger className="zcp2-btn zcp2-btn-ghost zcp2-mono">
                Resueltas ({resolvedDecisions.length})
              </Popover.Trigger>
              <Popover.Portal>
                <Popover.Positioner sideOffset={6} align="end">
                  <Popover.Popup className="zcp2-popover">
                    <div style={{ fontWeight: 700, fontSize: 11, marginBottom: 6 }}>
                      Decisiones resueltas recientes
                    </div>
                    {resolvedDecisions.length > 0 ? (
                      resolvedDecisions.map((ev) => (
                        <div key={ev.seq_id} className="zcp2-hist-item zcp2-mono">
                          <div>
                            <strong>{ev.task_id}</strong>{" "}
                            <span style={{ color: "var(--z2-faint)" }}>
                              ({formatAge(now, ev.ts_epoch)})
                            </span>
                          </div>
                          {ev.detail && (
                            <div style={{ color: "var(--z2-muted)" }}>{ev.detail}</div>
                          )}
                        </div>
                      ))
                    ) : (
                      <div className="zcp2-mono" style={{ color: "var(--z2-muted)", fontSize: 11 }}>
                        Sin decisiones resueltas en el stream actual.
                      </div>
                    )}
                  </Popover.Popup>
                </Popover.Positioner>
              </Popover.Portal>
            </Popover.Root>
          </div>
          <div className="zcp2-merge-list">
            {candidates.length ? (
              candidates.map((t) => (
                <div className="zcp2-merge-row zcp2-mono" key={t.task_id}>
                  <span style={{ fontWeight: 700 }}>{t.task_id}</span>
                  <span style={{ color: "var(--z2-muted)" }}>{t.repository}</span>
                  <span style={{ color: "var(--z2-purple)" }}>
                    {typeof t.memory.merge_checkpoint === "object" &&
                    t.memory.merge_checkpoint &&
                    "phase" in t.memory.merge_checkpoint
                      ? String(t.memory.merge_checkpoint.phase)
                      : "Fase no disponible"}
                  </span>
                </div>
              ))
            ) : (
              <p style={{ padding: "5px 10px", color: "var(--z2-muted)", margin: 0, fontSize: 11 }}>
                Sin checkpoints de merge recibidos.
              </p>
            )}
          </div>

          <div className="zcp2-sec-head">
            <h2 id="events-heading" className="zcp2-sec-title">
              Eventos
              <span className="zcp2-count">{visibleFeed.length}/200</span>
            </h2>
            <div className="zcp2-events-filters">
              {(
                [
                  ["ALL", "ALL"],
                  ["STAGE", "STAGE"],
                  ["DECISION", "DECISION"],
                  ["ERR", "ERR"],
                ] as const
              ).map(([kind, label]) => (
                <button
                  key={kind}
                  type="button"
                  className="zcp2-chip zcp2-mono"
                  aria-pressed={eventFilter === kind}
                  onClick={() => setEventFilter(kind)}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <ol className="zcp2-events-feed zcp2-mono">
            {visibleFeed.map((e) => (
              <li key={e.seq_id} className="zcp2-ev-row">
                <time className="zcp2-ev-time">
                  {new Date(e.ts_epoch * 1000).toLocaleTimeString("es")}
                </time>
                <span className={`zcp2-ev-type ${eventTone(e.event_type)}`}>
                  {e.event_type}
                </span>
                <button
                  type="button"
                  className="zcp2-ev-task"
                  onClick={() => setQuery(e.task_id === query ? "" : e.task_id)}
                >
                  {e.task_id}
                </button>
                <span className="zcp2-ev-detail" title={e.detail}>
                  {e.detail ?? ""}
                </span>
              </li>
            ))}
            {!visibleFeed.length && (
              <li style={{ padding: "6px 10px", color: "var(--z2-muted)" }}>
                Esperando nuevos eventos del stream.
              </li>
            )}
          </ol>
        </aside>
      </main>

      {selectedTask && (
        <TaskDetailModal
          key={selectedTask.task_id}
          task={
            s.tasks.find((t) => t.task_id === selectedTask.task_id) ??
            selectedTask
          }
          state={s}
          detail={taskDetail}
          detailLoading={detailLoading}
          detailError={detailError}
          now={now}
          connection={connection.current ?? undefined}
          onClose={() => setSelectedTask(null)}
          onFilterEvents={(taskId) => {
            setQuery(taskId);
            setSelectedTask(null);
          }}
        />
      )}
      </div>
    </Tooltip.Provider>
  );
}

function formatDuration(startEpoch: number, endEpoch?: number): string {
  if (!endEpoch || endEpoch < startEpoch) return "En curso";
  const secs = endEpoch - startEpoch;
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
}

function formatTokens(n?: number): string {
  if (n == null) return "—";
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}

export function TaskDetailModal({
  task,
  state,
  detail,
  detailLoading,
  detailError,
  now,
  connection,
  onClose,
  onFilterEvents,
}: {
  task: Task;
  state: State;
  detail: TaskDetail | null;
  detailLoading: boolean;
  detailError: string;
  now: number;
  connection?: Connection;
  onClose: () => void;
  onFilterEvents: (taskId: string) => void;
}) {
  const [tab, setTab] = useState<"summary" | "attempts">("summary");
  const activeTask = detail?.task ?? task;
  const openDec = taskDecision(state, activeTask);
  const lastCheckFailure =
    typeof activeTask.memory.last_check_failure === "string"
      ? activeTask.memory.last_check_failure
      : undefined;
  const approvedPlan =
    typeof activeTask.memory.approved_plan === "string"
      ? activeTask.memory.approved_plan
      : undefined;
  const issueUrl = github(activeTask, "issue");
  const pullUrl = github(activeTask, "pull");
  const auditByAttempt = useMemo(() => {
    const map = new Map<string, AttemptAudit>();
    for (const audit of detail?.audits ?? []) {
      map.set(audit.attempt_id, audit);
    }
    return map;
  }, [detail]);
  const cp = detail?.context_pack;
  const hasContextPack = Boolean(
    cp &&
      (cp.target_files.length ||
        cp.forbidden_paths.length ||
        cp.worker_checks.length ||
        cp.gate_checks.length ||
        cp.human_operations.length ||
        cp.verification_commands.length ||
        cp.acceptance_criteria.length ||
        cp.base_sha ||
        cp.network),
  );
  const isBrowser = typeof document !== "undefined";
  const body = (
    <>
      <div className="zcp2-dialog-head">
        <div>
          <div className="zcp2-mono" style={{ color: "var(--z2-accent)", fontSize: 11 }}>
            {activeTask.task_id} · {activeTask.repository} · Peso {activeTask.weight}
          </div>
          {isBrowser ? (
            <Dialog.Title style={{ margin: "2px 0 0", fontSize: 15, fontWeight: 700 }}>
              {activeTask.title}
            </Dialog.Title>
          ) : (
            <h2 style={{ margin: "2px 0 0", fontSize: 15, fontWeight: 700 }}>
              {activeTask.title}
            </h2>
          )}
        </div>
        {isBrowser ? (
          <Dialog.Close className="zcp2-btn">Cerrar</Dialog.Close>
        ) : (
          <button type="button" className="zcp2-btn" onClick={onClose}>
            Cerrar
          </button>
        )}
      </div>
      {isBrowser ? (
        <Dialog.Description className="zcp2-sr-only">
          Diagnóstico detallado, Context Pack e historial de intentos para {activeTask.task_id}.
        </Dialog.Description>
      ) : (
        <p className="zcp2-sr-only">
          Diagnóstico detallado, Context Pack e historial de intentos para {activeTask.task_id}.
        </p>
      )}
          <div className="zcp2-dialog-meta zcp2-mono">
            <div>Estado: {activeTask.status}</div>
            <div>GitHub: {activeTask.board_status ?? "Desconocido"}</div>
            <div>Etapa actual: {activeTask.current_stage ?? "—"}</div>
            <div>Actualizado: {formatAge(now, activeTask.updated_epoch)}</div>
          </div>
          <div
            className="zcp2-stage-strip zcp2-mono"
            aria-label={`Pipeline de ${activeTask.task_id}`}
          >
            {activeTask.required_stages.length ? (
              activeTask.required_stages.map((stage) => {
                const st = state.stages[activeTask.task_id + ":" + stage];
                const done = activeTask.stages_completed.includes(stage);
                const fail =
                  !done && Boolean(st && /FAIL|ERROR/.test(st.status));
                const running =
                  !done &&
                  !fail &&
                  (st?.status === "RUNNING" ||
                    activeTask.current_stage === stage);
                const stateClass = done
                  ? "is-done"
                  : fail
                    ? "is-failed"
                    : running
                      ? "is-running"
                      : "is-pending";
                const stateText = done
                  ? "done"
                  : fail
                    ? "failed"
                    : running
                      ? "running"
                      : "pending";
                return (
                  <div
                    key={stage}
                    className={`zcp2-stage-pill ${stateClass}`}
                    title={`${stage}: ${stateText}`}
                  >
                    <span className={`zcp2-pip ${stateClass}`} aria-hidden="true" />
                    <span>{stage}</span>
                    <span className="zcp2-stage-st">{stateText}</span>
                  </div>
                );
              })
            ) : (
              <span className="zcp2-mono" style={{ color: "var(--z2-muted)", fontSize: 11 }}>
                Sin etapas requeridas
              </span>
            )}
          </div>
          <Tabs.Root
            className="zcp2-modal-tabs"
            value={tab}
            onValueChange={(v) => setTab(v as "summary" | "attempts")}
          >
            <Tabs.List className="zcp2-tabs-list" aria-label="Secciones de la tarea">
              <Tabs.Tab className="zcp2-tab" value="summary">
                Resumen &amp; Context Pack
              </Tabs.Tab>
              <Tabs.Tab className="zcp2-tab" value="attempts">
                Intentos &amp; Auditoría{detail ? ` (${detail.attempts.length})` : ""}
              </Tabs.Tab>
            </Tabs.List>

            <Tabs.Panel className="zcp2-modal-panel" value="summary">
              {connection && (
                <div className="zcp2-dialog-section">
                  <div className="zcp2-dialog-label">Asistente IA</div>
                  <AiExplanationPanel
                    taskId={activeTask.task_id}
                    connection={connection}
                  />
                </div>
              )}
              {openDec && (
                <div className="zcp2-dialog-section zcp2-dialog-decision">
                  <div style={{ color: "var(--z2-accent)", fontSize: 11.5, fontWeight: 600 }}>
                    Decisión abierta: {openDec.question}
                  </div>
                  {openDec.context_summary && (
                    <p className="zcp2-dec-context" style={{ marginTop: 4 }}>
                      {openDec.context_summary}
                    </p>
                  )}
                </div>
              )}
            {lastCheckFailure && (
              <div className="zcp2-dialog-section zcp2-dialog-err">
                <div className="zcp2-dialog-label">Último fallo de verificación</div>
                <pre className="zcp2-pre zcp2-mono">{lastCheckFailure}</pre>
              </div>
            )}
            {approvedPlan && (
              <details className="zcp2-details zcp2-dialog-section">
                <summary>Plan aprobado</summary>
                <pre className="zcp2-pre zcp2-mono">{approvedPlan}</pre>
              </details>
            )}
            {detailLoading && (
              <div className="zcp2-dialog-section zcp2-mono zcp2-detail-note">
                Cargando Context Pack e historial…
              </div>
            )}
            {detailError && (
              <div className="zcp2-dialog-section zcp2-dialog-err">
                <div className="zcp2-dialog-label">Error de detalle</div>
                <div className="zcp2-mono" style={{ fontSize: 11 }}>{detailError}</div>
              </div>
            )}
            {cp && (
              <div className="zcp2-dialog-section zcp2-context-pack">
                <div className="zcp2-dialog-label">Context Pack</div>
                {!hasContextPack ? (
                  <div className="zcp2-mono zcp2-detail-note">Sin Context Pack registrado.</div>
                ) : (
                  <div className="zcp2-cp-body zcp2-mono">
                    {(cp.weight || cp.network || cp.base_sha) && (
                      <div className="zcp2-cp-meta">
                        {cp.weight && <span>Peso: {cp.weight}</span>}
                        {cp.network && <span>Red: {cp.network}</span>}
                        {cp.base_sha && <span>Base SHA: {cp.base_sha.slice(0, 12)}</span>}
                      </div>
                    )}
                    {cp.target_files.length > 0 && (
                      <div className="zcp2-cp-group">
                        <div className="zcp2-cp-sub">Archivos objetivo ({cp.target_files.length})</div>
                        <ul className="zcp2-cp-list">
                          {cp.target_files.map((f, i) => (
                            <li key={`${f.path}-${i}`}>
                              <span className="zcp2-cp-action">[{f.action || "modify"}]</span>{" "}
                              <span>{f.path}</span>
                              {f.summary && <span className="zcp2-cp-summary"> — {f.summary}</span>}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {cp.forbidden_paths.length > 0 && (
                      <div className="zcp2-cp-group">
                        <div className="zcp2-cp-sub">Rutas prohibidas</div>
                        <ul className="zcp2-cp-list">
                          {cp.forbidden_paths.map((p, i) => (
                            <li key={`${p}-${i}`}>{p}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {cp.acceptance_criteria.length > 0 && (
                      <div className="zcp2-cp-group">
                        <div className="zcp2-cp-sub">Criterios de aceptación</div>
                        <ul className="zcp2-cp-list">
                          {cp.acceptance_criteria.map((ac) => (
                            <li key={ac.id}>
                              <strong>{ac.id}:</strong> {ac.description}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {(cp.worker_checks.length > 0 || cp.gate_checks.length > 0 || cp.verification_commands.length > 0) && (
                      <div className="zcp2-cp-group">
                        <div className="zcp2-cp-sub">Verificaciones</div>
                        <ul className="zcp2-cp-list">
                          {[...cp.worker_checks, ...cp.gate_checks, ...cp.verification_commands].map((cmd, i) => (
                            <li key={`${cmd}-${i}`}>{cmd}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
            {detail && (
              <div className="zcp2-dialog-section">
                <div className="zcp2-dialog-label">
                  Historial de decisiones ({detail.decisions.length})
                </div>
                {detail.decisions.length === 0 ? (
                  <div className="zcp2-mono zcp2-detail-note">Sin decisiones registradas.</div>
                ) : (
                  <ul className="zcp2-dec-history">
                    {detail.decisions.map((dec) => (
                      <li key={dec.decision_id} className="zcp2-dec-hist-item">
                        <div className="zcp2-dec-hist-top zcp2-mono">
                          <span className={`zcp2-badge zcp2-badge-${dec.status.toLowerCase()}`}>
                            {dec.status}
                          </span>
                          <span>{dec.kind}</span>
                          <span>{dec.decision_id}</span>
                        </div>
                        <div className="zcp2-dec-hist-q">{dec.question}</div>
                        <div className="zcp2-dec-hist-meta zcp2-mono">
                          {dec.choice && <span>Elección: {dec.choice}</span>}
                          {dec.resolved_by && <span>Por: {dec.resolved_by}</span>}
                          {dec.retirement_reason && <span>Retirada: {dec.retirement_reason}</span>}
                          {dec.note && <span>Nota: {dec.note}</span>}
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
            </Tabs.Panel>

            <Tabs.Panel className="zcp2-modal-panel" value="attempts">
              {detailLoading ? (
                <div className="zcp2-dialog-section zcp2-mono zcp2-detail-note">
                  Cargando intentos y auditoría…
                </div>
              ) : detailError ? (
                <div className="zcp2-dialog-section zcp2-dialog-err">
                  <div className="zcp2-dialog-label">Error al cargar intentos</div>
                  <div className="zcp2-mono" style={{ fontSize: 11 }}>{detailError}</div>
                </div>
              ) : !detail || detail.attempts.length === 0 ? (
                <div className="zcp2-dialog-section zcp2-mono zcp2-detail-note">
                  Sin intentos registrados para esta tarea.
                </div>
              ) : (
                <div className="zcp2-attempts-list">
                  {detail.attempts.map((att) => {
                    const audit = auditByAttempt.get(att.attempt_id);
                    const tone = /PASS|SUCCEED|DONE|OK/.test(att.status)
                      ? "is-ok"
                      : /FAIL|ERROR|KILL|TIMEOUT/.test(att.status)
                        ? "is-err"
                        : "is-warn";
                    return (
                      <article key={att.attempt_id} className="zcp2-attempt-card">
                        <div className="zcp2-attempt-head zcp2-mono">
                          <span className={`zcp2-badge ${tone}`}>{att.status}</span>
                          <strong>{att.stage}</strong>
                          <span>{att.model} ({att.effort})</span>
                          <span>{formatDuration(att.started_epoch, att.ended_epoch)}</span>
                        </div>
                        <div className="zcp2-attempt-meta zcp2-mono">
                          <span>ID: {att.attempt_id}</span>
                          <span>Fase: {att.phase}</span>
                          <span>Tokens: {formatTokens(att.total_tokens)} (in {formatTokens(att.input_tokens)} / out {formatTokens(att.output_tokens)})</span>
                          {att.exit_code != null && (
                            <span>Exit: {att.exit_code}{att.exit_code_kind ? ` (${att.exit_code_kind})` : ""}</span>
                          )}
                          {att.failure_class && <span>Fallo: {att.failure_class}</span>}
                        </div>
                        {audit && (
                          <div className="zcp2-audit-grid zcp2-mono">
                            <span>Turnos: {audit.turn_count}</span>
                            <span>Tools: {audit.tool_call_count} (err {audit.tool_error_count})</span>
                            <span>Bucles edit/fail: {audit.edit_compile_fail_loops}</span>
                            <span>Lecturas redund.: {audit.redundant_read_count}</span>
                            {audit.cached_input_tokens != null && (
                              <span>Cache in: {formatTokens(audit.cached_input_tokens)}</span>
                            )}
                            {audit.reasoning_tokens != null && (
                              <span>Reasoning: {formatTokens(audit.reasoning_tokens)}</span>
                            )}
                            {audit.check_divergence && (
                              <span className="is-err">Divergencia check</span>
                            )}
                            {audit.error_code && (
                              <span className="is-err">Código: {audit.error_code}</span>
                            )}
                          </div>
                        )}
                        {att.summary && (
                          <pre className="zcp2-pre zcp2-mono">{att.summary}</pre>
                        )}
                      </article>
                    );
                  })}
                </div>
              )}
            </Tabs.Panel>
          </Tabs.Root>

          <div style={{ display: "flex", gap: 6, justifyContent: "flex-end", marginTop: 10, flexWrap: "wrap" }}>
            {issueUrl && (
              <a
                className="zcp2-btn zcp2-link"
                href={issueUrl}
                target="_blank"
                rel="noreferrer"
              >
                Issue ↗
              </a>
            )}
            {pullUrl && (
              <a
                className="zcp2-btn zcp2-link"
                href={pullUrl}
                target="_blank"
                rel="noreferrer"
              >
                PR #{activeTask.pr_number} ↗
              </a>
            )}
            <button
              type="button"
              className="zcp2-btn"
              onClick={() => onFilterEvents(activeTask.task_id)}
            >
              Filtrar eventos
            </button>
          </div>
    </>
  );
  if (!isBrowser) {
    return (
      <div className="zcp2-dialog-backdrop">
        <div className="zcp2-dialog-popup" role="dialog" aria-modal="true">
          {body}
        </div>
      </div>
    );
  }
  return (
    <Dialog.Root open onOpenChange={(open) => { if (!open) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Backdrop className="zcp2-dialog-backdrop" />
        <Dialog.Popup className="zcp2-dialog-popup">{body}</Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

if (typeof document !== "undefined") {
  const root = document.getElementById("root");
  if (root) {
    createRoot(root).render(
      <React.StrictMode>
        <App />
      </React.StrictMode>,
    );
  }
}
