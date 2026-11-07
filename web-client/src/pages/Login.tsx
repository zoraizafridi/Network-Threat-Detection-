import { useLayoutEffect, useRef, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { gsap } from "gsap";
import { HttpStatusError, readJson } from "../api";
import { useApp } from "../store";
import { useReducedMotion } from "../useReducedMotion";
import { SYSTEM_NAME } from "../brand";

export function Login() {
  const reduced = useReducedMotion();
  const navigate = useNavigate();
  const setUser = useApp((state) => state.setUser);
  const root = useRef<HTMLElement>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [failed, setFailed] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const [hint, setHint] = useState(false);

  useLayoutEffect(() => {
    const stage = root.current;
    if (!stage || reduced) return;
    const card = stage.querySelector(".access-card");
    const left = stage.querySelectorAll<HTMLElement>(".access-brand, .access-visual-copy > *, .access-line");
    const right = stage.querySelectorAll<HTMLElement>(".access-form > *");
    const ctx = gsap.context(() => {
      if (card) gsap.from(card, { scale: 0.98, autoAlpha: 0, duration: 0.8, ease: "power3.out" });
      gsap.from(left, { y: 20, autoAlpha: 0, duration: 0.8, stagger: 0.1, ease: "power3.out" });
      gsap.from(right, { y: 20, autoAlpha: 0, duration: 0.8, stagger: 0.05, delay: 0.15, ease: "power3.out" });
    }, stage);
    return () => ctx.revert();
  }, [reduced]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setFailed(false);
    setBlocked(false);
    try {
      const body = await readJson<{ username: string; role: string }>("/api/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      setUser(body);
      navigate("/portal");
    } catch (error) {
      if (error instanceof HttpStatusError && error.status === 401) {
        setFailed(true);
      }
      if (error instanceof HttpStatusError && error.status === 429) {
        setBlocked(true);
      }
    }
  }

  return (
    <main className="access" ref={root}>
      <section className="access-card">
        <div className="access-visual">
          <p className="access-brand">{SYSTEM_NAME}</p>
          <div className="access-visual-copy">
            <h1>Welcome back.</h1>
            <p>Secure access to the network topology, incident planner, and response engine.</p>
          </div>
          <p className="access-line">System status: Operational // Role-gated session</p>
        </div>
        <form className="access-form" onSubmit={submit}>
          <p className="access-kicker">Authenticate</p>
          <label>
            Username
            <input
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="username"
              autoFocus
            />
          </label>
          <label className="pass">
            Password
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
            />
          </label>
          {failed ? <p className="access-fail" role="alert">Sign in failed.</p> : null}
          {blocked ? <p className="access-fail" role="alert">Too many attempts. Wait a few minutes.</p> : null}
          <button type="submit">Initialize session</button>
          <button type="button" className="access-forgot" onClick={() => setHint(true)}>
            Forgot password?
          </button>
          {hint ? <p className="access-hint">Passphrases are issued with the account.</p> : null}
        </form>
      </section>
    </main>
  );
}
