import { afterEach, it, expect, vi } from "vitest";
import { Sound } from "./sound";
afterEach(() => vi.unstubAllGlobals());
it("stays silent until explicit enable, limits event kinds, hidden and mute stop audio", async () => {
  const start = vi.fn();
  const node = {
    type: "",
    frequency: { setValueAtTime: vi.fn() },
    connect: vi.fn(),
    start,
    stop: vi.fn(),
  };
  class Audio {
    state = "running";
    currentTime = 0;
    destination = {};
    resume = vi.fn(async () => {});
    suspend = vi.fn(async () => {});
    close = vi.fn(async () => {});
    createOscillator = () => node;
    createGain = () => ({
      gain: { setValueAtTime: vi.fn(), exponentialRampToValueAtTime: vi.fn() },
      connect: vi.fn(),
    });
  }
  vi.stubGlobal("AudioContext", Audio);
  vi.stubGlobal("document", { hidden: false });
  const s = new Sound();
  s.play("DECISION_REQUIRED");
  expect(start).not.toHaveBeenCalled();
  await s.toggle();
  s.play("STAGE_STARTED");
  s.play("DECISION_REQUIRED");
  s.play("MERGE_COMPLETED");
  expect(start).toHaveBeenCalledTimes(2);
  vi.stubGlobal("document", { hidden: true });
  s.play("DECISION_REQUIRED");
  expect(start).toHaveBeenCalledTimes(2);
  s.mute();
  expect(s.enabled).toBe(false);
  s.close();
});
it("a pending audio gesture cannot reenable sound after disconnect/mute", async () => {
  let resume!: () => void;
  class Audio {
    state = "running";
    resume = () =>
      new Promise<void>((r) => {
        resume = r;
      });
    suspend = async () => {};
    close = async () => {};
  }
  vi.stubGlobal("AudioContext", Audio);
  vi.stubGlobal("document", { hidden: false });
  const sound = new Sound();
  const pending = sound.toggle();
  sound.mute();
  resume();
  await pending;
  expect(sound.enabled).toBe(false);
  sound.close();
});
