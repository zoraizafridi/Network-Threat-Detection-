import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(process.cwd(), "src");
const SOURCE_FILE = /\.(css|ts|tsx)$/;
const WHITE = /#fff(?:fff)?\b/gi;
const TEXT_PROPERTIES = new Set(["color", "fill", "-webkit-text-fill-color", "caret-color", "text-decoration-color"]);
/* White text is only allowed on a filled control, so name the exact file here if that ever happens. */
const ALLOW: string[] = [];

function walk(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return walk(path);
    return SOURCE_FILE.test(entry.name) ? [path] : [];
  });
}

const files = walk(SRC);

function relative(file: string): string {
  return file.slice(SRC.length + 1).replace(/\\/g, "/");
}

function isTextColour(text: string, index: number): boolean {
  const head = text.slice(Math.max(0, index - 80), index);
  const property = /([a-z-]+)\s*[:=]\s*["']?[^;"'=]*$/i.exec(head)?.[1];
  return property ? TEXT_PROPERTIES.has(property.toLowerCase()) : false;
}

function luminance(hex: string): number {
  const channels = [1, 3, 5].map((offset) => parseInt(hex.slice(offset, offset + 2), 16) / 255);
  const [r, g, b] = channels.map((channel) =>
    channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4,
  );
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(foreground: string, background: string): number {
  const [light, dark] = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
  return (light + 0.05) / (dark + 0.05);
}

describe("palette tokens", () => {
  it("never uses white as a text colour", () => {
    const offenders: string[] = [];
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(WHITE)) {
        const at = match.index ?? 0;
        if (!isTextColour(text, at)) continue;
        const line = text.slice(0, at).split(/\r?\n/).length;
        if (ALLOW.includes(relative(file))) continue;
        offenders.push(`${relative(file)}:${line}`);
      }
    }
    expect(offenders, `White text is not allowed: ${offenders.join(", ")}`).toEqual([]);
  });

  it("defines the six palette tokens in the stylesheet token block", () => {
    const css = readFileSync(join(SRC, "styles.css"), "utf8");
    const tokens: Record<string, string> = {
      "--text-heading": "#E8DCC4",
      "--text-body": "#C9C2AC",
      "--text-label": "#A7B8AC",
      "--text-muted": "#7E9488",
      "--accent-gold": "#D9A05B",
      "--accent-lime": "#B7F36B",
      "--action-gold": "#D9A93A",
      "--action-ink": "#17120A",
    };
    for (const [name, value] of Object.entries(tokens)) {
      expect(css).toContain(`${name}: ${value};`);
    }
  });

  it("keeps every palette pair at WCAG AA or better", () => {
    const pairs: Array<[string, string, string]> = [
      ["heading on base", "#E8DCC4", "#050A07"],
      ["heading on surface", "#E8DCC4", "#0D1A12"],
      ["body on base", "#C9C2AC", "#050A07"],
      ["body on surface", "#C9C2AC", "#0D1A12"],
      ["label on base", "#A7B8AC", "#050A07"],
      ["label on surface", "#A7B8AC", "#0D1A12"],
      ["muted on base", "#7E9488", "#050A07"],
      ["muted on surface", "#7E9488", "#0D1A12"],
      ["gold on base", "#D9A05B", "#050A07"],
      ["gold on surface", "#D9A05B", "#0D1A12"],
      ["ink on lime", "#0C1A05", "#B7F36B"],
      ["button ink on gold", "#17120A", "#D9A93A"],
    ];
    const failures: string[] = [];
    for (const [label, foreground, background] of pairs) {
      const value = contrast(foreground, background);
      if (value < 4.5) failures.push(`${label} ${value.toFixed(2)}:1`);
    }
    expect(failures, `Below WCAG AA 4.5:1: ${failures.join(", ")}`).toEqual([]);
  });

  it("leaves none of the old cool off-white colours behind", () => {
    const legacy = ["#E6EEE9", "#F3F6F4", "#9FB0A6", "#6B7D73", "#A9BAB0", "230, 238, 233"];
    for (const file of files) {
      const text = readFileSync(file, "utf8").toUpperCase();
      for (const value of legacy) {
        expect(text, `${relative(file)} still uses ${value}`).not.toContain(value.toUpperCase());
      }
    }
  });
});

describe("map sizing", () => {
  /* A 65vh minimum on the flat map won on specificity over the stage's fixed height
     and pushed the SVG past the card border, so the drawing was clipped at the
     bottom. The map fills its stage, never the viewport. */
  it("never sizes the flat map with viewport units", () => {
    const css = readFileSync(join(SRC, "styles.css"), "utf8");
    const offenders = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)]
      .filter(([, selector]) => selector.includes(".flat-map"))
      .filter(([, , body]) => /min-height\s*:\s*[\d.]+(?:lvh|svh|dvh|vh|vw)/.test(body))
      .map(([, selector]) => selector.trim().replace(/\s+/g, " "));
    expect(offenders, `The flat map must fill its stage: ${offenders.join(" | ")}`).toEqual([]);
  });
});
