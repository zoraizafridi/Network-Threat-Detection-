export function FieldFigure() {
  return (
    <svg className="field-figure" viewBox="0 0 640 720" role="img" aria-label="Network of field hosts">
      <rect width="640" height="720" fill="#1F3D2B" />
      <circle cx="470" cy="180" r="220" fill="#2A4F39" />
      <circle cx="160" cy="540" r="160" fill="#2A4F39" />
      <g fill="none" stroke="#E8DCC4" strokeWidth="2">
        <path d="M180 210 L320 150 L470 230 L390 360 L230 340 Z" />
        <path d="M320 150 L300 300" />
        <path d="M470 230 L520 420" />
        <path d="M230 340 L180 470" />
        <path d="M390 360 L300 480 L180 470" />
        <path d="M520 420 L430 520 L300 480" />
      </g>
      <g fill="#E8DCC4">
        <circle cx="180" cy="210" r="14" />
        <circle cx="320" cy="150" r="18" />
        <circle cx="470" cy="230" r="22" />
        <circle cx="390" cy="360" r="12" />
        <circle cx="230" cy="340" r="10" />
        <circle cx="300" cy="300" r="8" />
        <circle cx="520" cy="420" r="14" />
        <circle cx="180" cy="470" r="16" />
        <circle cx="300" cy="480" r="11" />
        <circle cx="430" cy="520" r="9" />
      </g>
      <g fill="#1F3D2B" fontFamily="IBM Plex Mono, monospace" fontSize="13">
        <text x="196" y="214">R1</text>
        <text x="338" y="154">R2</text>
        <text x="492" y="234">CORE</text>
      </g>
    </svg>
  );
}
