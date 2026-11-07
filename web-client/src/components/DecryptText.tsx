import { useEffect, useState } from "react";
import { gsap } from "gsap";
import { useReducedMotion } from "../useReducedMotion";

const GLYPHS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

export function DecryptText({ text }: { text: string }) {
  const reduced = useReducedMotion();
  const [shown, setShown] = useState(text);

  useEffect(() => {
    if (reduced) {
      setShown(text);
      return;
    }
    const state = { step: 0 };
    const tween = gsap.to(state, {
      step: text.length,
      duration: 0.9,
      ease: "power3.out",
      onUpdate: () => {
        const done = Math.floor(state.step);
        let next = text.slice(0, done);
        for (let i = done; i < text.length; i += 1) {
          const source = text[i];
          if (source === " ") {
            next += " ";
          } else {
            next += GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
          }
        }
        setShown(next);
      },
      onComplete: () => setShown(text),
    });
    return () => tween.kill();
  }, [text, reduced]);

  return <span className="mono">{shown}</span>;
}
