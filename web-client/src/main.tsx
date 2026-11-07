import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { gsap } from "gsap";
import { App } from "./App";
import "./styles.css";

gsap.ticker.fps(60);
gsap.ticker.lagSmoothing(0);

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
