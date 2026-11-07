export const MAP = {
  bg: 0x07100b,
  grid: 0x1b3025,
  link: 0x5cb8d6,
  nodeHealthy: 0xa9c4b3,
  ringHealthy: 0x2f9e6f,
  probed: 0xe8c547,
  compromised: 0xe5604f,
  isolated: 0x7d8fa3,
  selection: 0xd9a050,
} as const;

export const MAP_HEMI = { skyColor: 0xdfeee5, groundColor: 0x07100b, intensity: 0.9 };
export const MAP_DIR = { color: 0xffffff, intensity: 0.8, position: [-30, 50, 20] as [number, number, number] };