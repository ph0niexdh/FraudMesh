import { SEV_COLOR, severityOf } from "../lib/format";

/** Hero number with a semicircular meter — risk 0–100. */
export function RiskGauge({ score, size = 200, severity }: { score: number; size?: number; severity?: string }) {
  const sev = severity ?? severityOf(score);
  const color = SEV_COLOR[sev] ?? "#2dd4bf";
  const r = size / 2 - 12;
  const cx = size / 2;
  const cy = size / 2;
  const circ = Math.PI * r;
  const frac = Math.max(0, Math.min(100, score)) / 100;
  const arc = `M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`;
  return (
    <div className="relative flex flex-col items-center" style={{ width: size }}>
      <svg width={size} height={size / 2 + 14} viewBox={`0 0 ${size} ${size / 2 + 14}`} role="img"
           aria-label={`Risk score ${Math.round(score)} of 100, ${sev}`}>
        <path d={arc} stroke="#1b2733" strokeWidth={12} fill="none" strokeLinecap="round" />
        <path d={arc} stroke={color} strokeWidth={12} fill="none" strokeLinecap="round"
              strokeDasharray={`${circ}`} strokeDashoffset={circ * (1 - frac)}
              style={{ transition: "stroke-dashoffset 900ms ease-out, stroke 600ms" }} />
        {[30, 60, 80].map((t) => {
          const a = Math.PI * (1 - t / 100);
          return <line key={t} x1={cx + (r - 9) * Math.cos(a)} y1={cy - (r - 9) * Math.sin(a)}
                       x2={cx + (r + 9) * Math.cos(a)} y2={cy - (r + 9) * Math.sin(a)} stroke="#0d141b" strokeWidth={2} />;
        })}
      </svg>
      <div className="absolute flex flex-col items-center" style={{ top: size / 2 - 44 }}>
        <div className="font-mono font-semibold tabular-nums leading-none" style={{ fontSize: size / 4.2, color }}>
          {Math.round(score)}
        </div>
        <div className="text-[11px] text-fg-muted mt-1">/ 100</div>
      </div>
    </div>
  );
}
