import { useEffect, useRef } from "react";
import { gsap } from "gsap";
import { motionMs } from "../motion";
import { useReducedMotion } from "../useReducedMotion";

export function Count({ value }: { value: number }) {
  const reduced = useReducedMotion();
  const ref = useRef<HTMLSpanElement>(null);
  const shown = useRef(value);

  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    if (reduced || motionMs(350, reduced) === 0) {
      shown.current = value;
      node.textContent = String(value);
      return;
    }
    const state = { n: shown.current };
    const tween = gsap.to(state, {
      n: value,
      duration: 0.35,
      ease: "power3.out",
      onUpdate: () => {
        if (ref.current) ref.current.textContent = String(Math.round(state.n));
      },
    });
    shown.current = value;
    return () => {
      tween.kill();
    };
  }, [value, reduced]);

  return <span ref={ref}>{value}</span>;
}
