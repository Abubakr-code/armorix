import { gradeColor } from "../util";

// Security score 0–100 as a ring with the letter grade in the middle.
export default function ScoreRing({ score = 100, grade = "A", size = 120, stroke = 10, label }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const color = gradeColor(grade);
  return (
    <div className="score-ring" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--line)" strokeWidth={stroke} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - score / 100)}
          transform={`rotate(-90 ${size / 2} ${size / 2})`}
          style={{ transition: "stroke-dashoffset 0.8s cubic-bezier(.2,.8,.2,1)" }}
        />
      </svg>
      <div className="score-ring-inner">
        <b style={{ color, fontSize: size * 0.3 }}>{grade}</b>
        <span style={{ fontSize: Math.max(10, size * 0.11) }}>{label ?? `${score}/100`}</span>
      </div>
    </div>
  );
}
