import {
  event,
  object,
  snapshot,
  string,
  integer,
  decision,
  type Decision,
} from "./protocol";
import { acceptSnapshot, applyEvent, initial, type State } from "./state";
import { SSEParser } from "./sse";
class Halt extends Error {}
export class Connection {
  private token = "";
  private controller?: AbortController;
  private generation = 0;
  private retry?: ReturnType<typeof setTimeout>;
  private attempt = 0;
  private synced = false;
  state: State = initial;
  constructor(
    private change: (s: State) => void,
    private notice: (s: string) => void,
    private sound: (kind: string) => void = () => {},
  ) {}
  get active() {
    return !!this.token && !!this.controller && !this.controller.signal.aborted;
  }
  private update(s: State) {
    this.state = s;
    this.change(s);
  }
  private options(signal: AbortSignal, extra: RequestInit = {}): RequestInit {
    return {
      ...extra,
      signal,
      credentials: "same-origin",
      redirect: "error",
      cache: "no-store",
      headers: { Authorization: `Bearer ${this.token}`, ...extra.headers },
    };
  }
  disconnect(message = "Desconectado") {
    this.generation++;
    this.controller?.abort();
    clearTimeout(this.retry);
    this.token = "";
    this.notice(message);
  }
  private async checked(response: Response, type: string, generation: number) {
    if (generation !== this.generation) throw new Halt();
    if (response.status === 401 || response.status === 403) {
      this.disconnect(
        "Acceso denegado. Vuelve a conectar con una credencial válida.",
      );
      throw new Halt();
    }
    if (!response.ok)
      throw Error(
        response.status === 503
          ? "Gateway sin capacidad; reconectando"
          : "Gateway no disponible",
      );
    if (!response.headers.get("content-type")?.includes(type))
      throw new Halt("Respuesta de protocolo no válida");
    return response;
  }
  async connect(token: string) {
    this.disconnect();
    if (!token.trim()) return;
    this.token = token;
    const gen = this.generation;
    this.controller = new AbortController();
    this.update(initial);
    this.attempt = 0;
    this.notice("Conectando");
    try {
      const r = await this.checked(
        await fetch("/api/snapshot", this.options(this.controller.signal)),
        "application/json",
        gen,
      );
      const value = snapshot(await r.json(), true);
      if (gen !== this.generation) return;
      this.update(acceptSnapshot(initial, value));
      void this.stream(gen);
    } catch (e) {
      if (gen !== this.generation) return;
      this.disconnect(
        e instanceof Halt
          ? e.message || "Acceso denegado"
          : "No se pudo obtener el snapshot. Conecta de nuevo.",
      );
    }
  }
  private async stream(gen: number) {
    if (gen !== this.generation || !this.controller) return;
    this.synced = false;
    const openedAt = Date.now();
    this.notice("Sincronizando stream");
    try {
      const r = await this.checked(
        await fetch(
          "/api/events",
          this.options(this.controller.signal, {
            headers: { "Last-Event-ID": String(this.state.cursor) },
          }),
        ),
        "text/event-stream",
        gen,
      );
      if (gen !== this.generation) return;
      if (!r.body) throw new Halt("Stream vacío");
      const reader = r.body.getReader();
      let resync = false;
      const parser = new SSEParser((frame) => {
        if (gen !== this.generation || resync) return;
        if (frame.event === "resync_required") {
          integer(object(JSON.parse(frame.data)).last_seq_id);
          resync = true;
          return;
        }
        if (frame.event === "snapshot") {
          const v = snapshot(JSON.parse(frame.data));
          this.update(acceptSnapshot(this.state, v));
          this.synced = true;
          this.notice(
            this.state.reset
              ? "Resincronizado: el historial del servidor cambió"
              : "Conectado · SSE",
          );
          return;
        }
        if (frame.event === "task_event") {
          if (!this.synced) throw new Halt("Evento antes del snapshot");
          const value = event(JSON.parse(frame.data));
          if (
            frame.id != null &&
            (!/^\d+$/.test(frame.id) ||
              integer(Number(frame.id)) !== value.seq_id)
          )
            throw new Halt("Cursor no válido");
          const previous = this.state;
          const next = applyEvent(previous, value);
          this.update(next);
          if (next !== previous && value.seq_id > next.watermark)
            this.sound(value.event_type);
        }
      });
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (gen !== this.generation) return;
          if (done) {
            try {
              parser.finish();
            } catch {
              throw new Halt("Stream no válido. Conecta de nuevo.");
            }
            break;
          }
          try {
            parser.push(value);
          } catch {
            throw new Halt("Stream no válido. Conecta de nuevo.");
          }
          if (resync) {
            await reader.cancel();
            break;
          }
        }
      } finally {
        reader.releaseLock();
      }
      if (Date.now() - openedAt >= 30000) this.attempt = 0;
      if (gen === this.generation)
        this.schedule(
          gen,
          resync ? "Resincronizando" : "Conexión interrumpida",
        );
    } catch (e) {
      if (gen !== this.generation) return;
      if (
        e instanceof Halt ||
        e instanceof SyntaxError ||
        (e instanceof TypeError && e.message.includes("UTF"))
      ) {
        this.disconnect(e.message || "Stream no válido");
        return;
      }
      if (
        e instanceof Error &&
        /válid|grande|snapshot|Objeto|Texto|Lista|número|Secuencia/.test(
          e.message,
        )
      ) {
        this.disconnect("Stream no válido. Conecta de nuevo.");
        return;
      }
      this.schedule(gen, "Gateway no disponible");
    }
  }
  private schedule(gen: number, message: string) {
    this.notice(message + " · reconectando");
    const delay = Math.min(
      30000,
      Math.max(
        1000,
        1000 * 2 ** Math.min(this.attempt++, 5) * (0.85 + Math.random() * 0.3),
      ),
    );
    this.retry = setTimeout(() => void this.stream(gen), delay);
  }
  async decide(
    id: string,
    choice: string,
    note: string,
  ): Promise<{ message: string; unknown: boolean; resolved?: Decision }> {
    const gen = this.generation;
    const signal = this.controller?.signal;
    if (!signal || !this.token)
      return { message: "Conecta para decidir", unknown: false };
    try {
      const r = await fetch(
        "/api/decide",
        this.options(signal, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            decision_id: id,
            choice,
            ...(note ? { note } : {}),
          }),
        }),
      );
      if (gen !== this.generation)
        return { message: "Conexión finalizada", unknown: true };
      if (r.status === 401) {
        this.disconnect("Credencial caducada");
        return { message: "Acceso denegado", unknown: true };
      }
      if (r.status === 403)
        return {
          message:
            "La política del servidor no permite este tipo de decisión. Las decisiones de merge están denegadas por defecto.",
          unknown: false,
        };
      if (r.status === 400)
        return {
          message: "Opción no válida. Revisa las opciones del servidor.",
          unknown: false,
        };
      if (r.status === 404)
        return {
          message: "Decisión no encontrada. Espera la sincronización.",
          unknown: true,
        };
      if (!r.ok)
        return {
          message:
            "Resultado desconocido. No se reintentó. Espera la reconciliación del stream.",
          unknown: true,
        };
      if (!r.headers.get("content-type")?.includes("application/json"))
        throw Error();
      const data = object(await r.json()),
        outcome = string(data.outcome);
      if (!["RESOLVED", "ALREADY_RESOLVED"].includes(outcome)) throw Error();
      const d = decision(data.decision);
      if (gen !== this.generation)
        return { message: "Conexión finalizada", unknown: true };
      if (d.decision_id !== id || !d.choice || d.status !== "RESOLVED")
        throw Error();
      const message = `${outcome === "ALREADY_RESOLVED" ? "Ya resuelta" : "Decisión confirmada"} · opción ganadora: ${d.choice}`;
      this.notice(message);
      return { message, unknown: false, resolved: d };
    } catch {
      return {
        message:
          "Resultado desconocido. No se reintentó. Espera la reconciliación del stream.",
        unknown: true,
      };
    }
  }
}
