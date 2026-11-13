export class Sound {
  private context?: AudioContext;
  private generation = 0;
  private pending = false;
  enabled = false;
  async toggle() {
    if (this.enabled || this.pending) {
      this.mute();
      return;
    }
    const generation = ++this.generation;
    this.pending = true;
    try {
      this.context ??= new AudioContext();
      await this.context.resume();
      if (generation !== this.generation || document.hidden) {
        void this.context.suspend().catch(() => {});
        return;
      }
      this.enabled = this.context.state === "running";
    } catch {
      this.mute();
    } finally {
      if (generation === this.generation) this.pending = false;
    }
  }
  mute() {
    this.generation++;
    this.pending = false;
    this.enabled = false;
    void this.context?.suspend().catch(() => {});
  }
  play(kind: string) {
    if (
      !this.enabled ||
      document.hidden ||
      !["DECISION_REQUIRED", "MERGE_COMPLETED"].includes(kind) ||
      !this.context
    )
      return;
    try {
      const c = this.context,
        o = c.createOscillator(),
        g = c.createGain();
      o.type = "sine";
      o.frequency.setValueAtTime(
        kind === "DECISION_REQUIRED" ? 660 : 150,
        c.currentTime,
      );
      g.gain.setValueAtTime(0.025, c.currentTime);
      g.gain.exponentialRampToValueAtTime(0.001, c.currentTime + 0.2);
      o.connect(g);
      g.connect(c.destination);
      o.start();
      o.stop(c.currentTime + 0.22);
    } catch {
      this.mute();
    }
  }
  close() {
    this.mute();
    void this.context?.close().catch(() => {});
    this.context = undefined;
  }
}
