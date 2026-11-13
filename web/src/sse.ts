export interface Frame {
  event: string;
  data: string;
  id?: string;
}
// Bound both an unfinished line and accumulated multiline event (backend frame is 4 MiB).
export const FRAME_LIMIT = 4 * 1024 * 1024 + 65536;
export class SSEParser {
  private decoder = new TextDecoder("utf-8", { fatal: true });
  private line = "";
  private lineBytes = 0;
  private frameBytes = 0;
  private data: string[] = [];
  private size = 0;
  private kind = "";
  private id: string | undefined;
  private cr = false;
  private first = true;
  constructor(
    private emit: (f: Frame) => void,
    private limit = FRAME_LIMIT,
  ) {}
  push(bytes: Uint8Array) {
    this.consume(this.decoder.decode(bytes, { stream: true }));
  }
  finish() {
    this.consume(
      this.decoder.decode(),
    ); /* EOF does not dispatch an unterminated event. */
  }
  private consume(text: string) {
    for (const c of text) {
      if (this.first) {
        this.first = false;
        if (c === "\uFEFF") continue;
      }
      if (this.cr) {
        this.cr = false;
        if (c === "\n") continue;
      }
      if (c === "\r" || c === "\n") {
        this.endLine();
        this.cr = c === "\r";
      } else {
        this.line += c;
        const point = c.codePointAt(0)!;
        const bytes =
          point <= 0x7f ? 1 : point <= 0x7ff ? 2 : point <= 0xffff ? 3 : 4;
        this.lineBytes += bytes;
        this.frameBytes += bytes;
        if (this.frameBytes > this.limit)
          throw Error("Stream demasiado grande");
        if (this.lineBytes + this.size > this.limit)
          throw Error("Stream demasiado grande");
      }
    }
  }
  private endLine() {
    const line = this.line;
    this.line = "";
    this.lineBytes = 0;
    if (!line) {
      this.frameBytes = 0;
      if (this.data.length)
        this.emit({
          event: this.kind || "message",
          data: this.data.join("\n"),
          id: this.id,
        });
      this.data = [];
      this.size = 0;
      this.kind = "";
      this.id = undefined;
      return;
    }
    if (line.startsWith(":")) return;
    const i = line.indexOf(":");
    const field = i < 0 ? line : line.slice(0, i);
    let value = i < 0 ? "" : line.slice(i + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    if (field === "data") {
      this.data.push(value);
      this.size += new TextEncoder().encode(value).length + 1;
      if (this.size > this.limit) throw Error("Stream demasiado grande");
    } else if (field === "event") this.kind = value;
    else if (field === "id" && !value.includes("\0")) this.id = value;
  }
}
