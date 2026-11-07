export const MAP = {
  bg: 0x07100b,
  grid: 0x1b3025,
  // The ground plate sits one step above the page background so the floor of the
  // scene reads as a surface, while the clear colour behind it stays the page green.
  ground: 0x10251a,
  groundLine: 0xa3b8ab,
  groundRim: 0x7d9c88,
  link: 0x6fa8ff,
  nodeHealthy: 0xa9c4b3,
  ringHealthy: 0x2f9e6f,
  probed: 0xf2c94c,
  compromised: 0xff6b6b,
  isolated: 0x7d8fa3,
  // Selection is an emphasis highlight, so it uses the gold accent.
  selection: 0xd9a05b,
} as const;

export const MAP_HEMI = { skyColor: 0xe8dcc4, groundColor: 0x07100b, intensity: 0.9 };
export const MAP_DIR = { color: 0xe8dcc4, intensity: 0.8, position: [-30, 50, 20] as [number, number, number] };