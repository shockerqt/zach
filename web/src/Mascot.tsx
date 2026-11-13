import { useId, useLayoutEffect, useMemo, useRef } from "react";
import raw from "../design/zach-mascot.svg?raw";
import { layers, type Mood } from "./state";
export const moodText: Record<Mood, string> = {
  idle: "Zach está de siesta",
  hunting: "Zach está cazando",
  review: "Zach revisa con atención",
  decision: "Zach espera tu decisión",
  merged: "Zach ronronea: merge completado",
  error: "Zach necesita tu atención",
  paused: "Zach está en pausa",
};
export function Mascot({
  mood,
  small = false,
}: {
  mood: Mood;
  small?: boolean;
}) {
  const prefix = useId().replaceAll(":", "");
  const root = useRef<HTMLDivElement>(null);
  const previous = useRef<string | undefined>(undefined);
  const svg = useMemo(
    () =>
      raw
        .replace(
          /id="([^"]+)" data-state-layer/g,
          (_, name: string) =>
            `id="${prefix}-${name}" data-layer="${name}" data-state-layer style="opacity:0;visibility:hidden"`,
        )
        .replace('<path d="M144 172', '<g class="tail"><path d="M144 172')
        .replace(
          'stroke-linecap="round"></path>',
          'stroke-linecap="round"></path></g>',
        )
        .replace('role="img" aria-label="Zach"', 'aria-hidden="true"'),
    [prefix],
  );
  useLayoutEffect(() => {
    const active = layers[mood];
    const outgoing = previous.current;
    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
    const groups = root.current?.querySelectorAll<SVGGElement>("[data-layer]");
    groups?.forEach((g) => {
      const name = g.dataset.layer!;
      const selected = active.includes(name);
      g.style.opacity = selected ? "1" : "0";
      g.style.visibility =
        selected ||
        (!reduce && name === outgoing && !active.includes(outgoing ?? ""))
          ? "visible"
          : "hidden";
    });
    previous.current = active.find((n) => n.startsWith("eyes-"));
    const timer = setTimeout(
      () =>
        groups?.forEach((g) => {
          if (!active.includes(g.dataset.layer!)) g.style.visibility = "hidden";
        }),
      reduce ? 0 : 200,
    );
    return () => clearTimeout(timer);
  }, [mood]);
  return (
    <div
      ref={root}
      className={`mascot ${small ? "small" : ""} ${mood}`}
      role="img"
      aria-label={moodText[mood]}
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}
