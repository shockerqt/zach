import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
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
import { github, type Task, type Decision } from "./protocol";
import { Mascot, moodText } from "./Mascot";
import { Sound } from "./sound";
function DecisionCard({
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
    <article className="card decision" aria-label={`Decisión ${d.decision_id}`}>
      <div className="eyebrow">{d.kind}</div>
      <div className="mono">
        {d.task_id} · {t?.weight ?? "Peso no disponible"}
      </div>
      <h2>{d.question}</h2>
      <p>{d.context_summary}</p>
      {issue && (
        <a href={issue} target="_blank" rel="noreferrer">
          Leer la tarea y sus revisiones ↗
        </a>
      )}
      {["merge_approval", "human-merge-approval"].includes(d.kind) && (
        <p className="meta">
          La política del servidor deniega merge por defecto.
        </p>
      )}
      <label>
        Nota (opcional)
        <input
          maxLength={2000}
          value={note}
          onChange={(e) => setNote(e.target.value)}
          disabled={pending || unknown || !connection.active}
        />
      </label>
      <div className="actions">
        {d.options.map((choice, i) => (
          <button
            key={choice}
            className={i === 0 ? "primary" : ""}
            disabled={pending || unknown || !connection.active}
            onClick={() => void choose(choice)}
          >
            {plan && choice === "Approve"
              ? "Aprobar"
              : plan && choice === "Reject"
                ? "Rechazar"
                : choice}
          </button>
        ))}
      </div>
      {message && (
        <p className="notice" role="status">
          {message}
        </p>
      )}
      <p className="meta">Las decisiones no se aprueban solas por tiempo.</p>
    </article>
  );
}
function TaskCard({ t, s }: { t: Task; s: State }) {
  const pr = github(t, "pull");
  const openDecision = taskDecision(s, t);
  return (
    <article className="card task">
      <div className="taskhead">
        <span className="id">{t.task_id}</span>
        <h3>{t.title}</h3>
        <span className="meta">
          {t.repository} · peso {t.weight}
        </span>
      </div>
      <ol className="stages">
        {t.required_stages.map((stage) => {
          const obs = s.stages[t.task_id + ":" + stage],
            done = t.stages_completed.includes(stage),
            fail = obs && /FAIL|ERROR/.test(obs.status),
            wait =
              s.decisions.some((d) => d.task_id === t.task_id) &&
              t.current_stage === stage;
          return (
            <li
              className={`stage ${fail ? "failure" : wait ? "wait" : ""}`}
              key={stage}
            >
              <b>
                {done ? "✓" : fail ? "×" : wait ? "●" : "○"} {stage}
              </b>
              <span className="meta">
                {obs?.model ?? "Modelo no disponible"} ·{" "}
                {obs?.duration != null
                  ? `${obs.duration} s`
                  : "Duración no disponible"}
              </span>
            </li>
          );
        })}
      </ol>
      <div className="taskfoot">
        <p className={t.memory.last_check_failure ? "failure" : ""}>
          {t.memory.last_check_failure ? "⚠ Fallo registrado · " : ""}
          Estado efectivo: {t.status} · GitHub: {t.board_status ?? "Desconocido"}
          {openDecision && (
            <span> · Decisión abierta: {openDecision.question} ({openDecision.decision_id})</span>
          )}
          {observedStage(s, t) && (
            <span> · Etapa observada: {observedStage(s, t)!.status}</span>
          )}
        </p>
        {pr && (
          <a className="action" href={pr} target="_blank" rel="noreferrer">
            Ver PR #{t.pr_number} ↗
          </a>
        )}
      </div>
      {!!t.memory.last_check_failure && (
        <>
          <button disabled>Reintentar merge</button>
          <small>
            Solo disponible mediante una opción de decisión abierta del
            servidor.
          </small>
        </>
      )}
    </article>
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
        <button className="primary" type="button" onClick={onReconnect}>
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
        Credencial de sesión
        <input
          ref={inputRef}
          type="password"
          autoComplete="off"
          name="session-credential"
          required
        />
      </label>
      <button className="primary" type="submit">
        Conectar
      </button>
      <button type="button" onClick={onDisconnect}>
        Desconectar
      </button>
      <p>
        Solo en memoria durante la conexión. El campo se borra al conectar.
      </p>
      <div className="status" role="status">
        {connected ? "● " : ""}
        {notice}
      </div>
    </form>
  );
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
    [eventFilter, setEventFilter] = useState<EventFilterKind>("ALL");
  const input = useRef<HTMLInputElement>(null),
    sound = useRef(new Sound()),
    connection = useRef<Connection | null>(null);
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
  useEffect(() => {
    void c.connectAuto();
    const timer = setInterval(() => setNow(Date.now()), 1000);
    const hide = () => {
      if (document.hidden) {
        sound.current.mute();
        setOn(false);
      }
    };
    document.addEventListener("visibilitychange", hide);
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", hide);
      c.disconnect();
      sound.current.close();
    };
  }, [c]);
  const currentMood = mood(s, false, now);
  const repos = Array.from(new Set(s.tasks.map((t) => t.repository))).sort();
  const active = sortTasksNewestFirst(
    s.tasks.filter((t) => taskLane(s, t) === "active" && matchesTaskFilter(t, query, repoFilter)),
  );
  const queued = sortTasksNewestFirst(
    s.tasks.filter((t) => taskLane(s, t) === "queued" && matchesTaskFilter(t, query, repoFilter)),
  );
  const candidates = s.tasks.filter((t) => t.memory.merge_checkpoint);
  const visibleFeed = filterEvents(s.feed, query, eventFilter);
  const connected =
    notice.includes("SSE") || notice.startsWith("Resincronizado");
  return (
    <div data-density={ultraDense ? "ultra" : "compact"}>
      <a className="skip" href="#main">
        Ir al contenido
      </a>
      <header>
        <div className="brand">
          <Mascot mood={currentMood} small />
          <h1>Zach</h1>
        </div>
        <div className="chips">
          <span className="chip">
            {s.status
              ? `Latido observado hace ${Math.max(0, Math.floor(now / 1000 - s.status.heartbeat_epoch))} s`
              : "Latido no disponible"}
          </span>
          <span className="chip">
            Slots{" "}
            {s.status
              ? `${s.status.running_task_slots} de ${s.status.max_parallel_tasks}`
              : "no disponibles"}
          </span>
          <span className="chip">En curso: {active.length}</span>
          <span className="chip">En cola: {queued.length}</span>
        </div>
        <div className="controls">
          <input
            type="search"
            className="filter-input"
            aria-label="Filtrar tareas y eventos"
            placeholder="Filtrar tarea, repo, evento..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <select
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
          <button
            type="button"
            aria-pressed={ultraDense}
            onClick={() => setUltraDense((u) => !u)}
          >
            {ultraDense ? "Densidad: Ultra" : "Densidad: Compacta"}
          </button>
          <button disabled title="No disponible en esta versión">
            Pausar cola
          </button>
          <button
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
      <main id="main">
        <section className="column" aria-label="Decisiones pendientes">
          {s.decisions.length ? (
            s.decisions.map((d) => (
              <DecisionCard
                key={d.decision_id}
                d={d}
                t={s.tasks.find((t) => t.task_id === d.task_id)}
                connection={c}
                epoch={epoch}
                syncVersion={s.syncVersion}
              />
            ))
          ) : (
            <div className="card empty">
              No hay decisiones abiertas en el último estado recibido.
            </div>
          )}
          <div className="card identity">
            <Mascot mood={currentMood} />
            <div>
              <h2>{moodText[currentMood]}</h2>
              <p className="meta">
                {s.decisions.length}{" "}
                {s.decisions.length === 1
                  ? "decisión abierta"
                  : "decisiones abiertas"}
              </p>
            </div>
          </div>
        </section>
        <section className="column" aria-label="Tareas">
          <div>
            <h2>En curso</h2>
            {active.length ? (
              active.map((t) => <TaskCard key={t.task_id} t={t} s={s} />)
            ) : (
              <p className="card empty">
                No hay tareas en curso en el último estado recibido.
              </p>
            )}
          </div>
          <div>
            <h2>En cola</h2>
            {queued.length ? (
              queued.map((t) => <TaskCard key={t.task_id} t={t} s={s} />)
            ) : (
              <p className="card empty">
                No hay tareas en cola en el último estado recibido.
              </p>
            )}
          </div>
        </section>
        <aside className="column right">
          <section className="card" aria-labelledby="merge-heading">
            <h2 id="merge-heading">Cola de merge</h2>
            <p className="meta">
              Vista parcial de checkpoints. El servidor no publica la cola FIFO
              completa.
            </p>
            {candidates.length ? (
              candidates.map((t) => (
                <div className="lane" key={t.task_id}>
                  <span>{t.repository}</span>
                  <span className="id">{t.task_id}</span>
                  <span className="meta">
                    {typeof t.memory.merge_checkpoint === "object" &&
                    t.memory.merge_checkpoint &&
                    "phase" in t.memory.merge_checkpoint
                      ? String(t.memory.merge_checkpoint.phase)
                      : "Fase no disponible"}
                  </span>
                </div>
              ))
            ) : (
              <p className="empty">Sin checkpoints de merge recibidos.</p>
            )}
          </section>
          <section className="card" aria-labelledby="events-heading">
            <div className="section-bar">
              <h2 id="events-heading">Eventos</h2>
              <div className="actions">
                {(
                  [
                    ["ALL", "Todos"],
                    ["STAGE", "Etapas"],
                    ["DECISION", "Decisiones"],
                    ["ERR", "Errores"],
                  ] as const
                ).map(([kind, label]) => (
                  <button
                    key={kind}
                    type="button"
                    aria-pressed={eventFilter === kind}
                    onClick={() => setEventFilter(kind)}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
            <p className="meta">
              {visibleFeed.length === 1
                ? "Mostrando 1 evento"
                : `Mostrando ${visibleFeed.length} eventos`}{" "}
              · total {s.feed.length} (máximo 200)
            </p>
            <ol className="events">
              {visibleFeed.map((e) => (
                <li key={e.seq_id}>
                  <time>
                    {new Date(e.ts_epoch * 1000).toLocaleTimeString("es")}
                  </time>
                  <span className="eventkind">{e.event_type}</span>
                  <span className="id">{e.task_id}</span>
                  {e.detail && <span className="meta">{e.detail}</span>}
                </li>
              ))}
            </ol>
            {!visibleFeed.length && (
              <p className="empty">Esperando nuevos eventos del stream.</p>
            )}
          </section>
          <p className="meta">
            El latido es una observación fechada; la conexión SSE no prueba
            actividad del daemon. Los cambios sin evento se verán en el próximo
            snapshot del stream.
          </p>
        </aside>
      </main>
    </div>
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
