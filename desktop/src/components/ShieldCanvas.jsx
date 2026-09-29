// The website's particle shield, drawn with Canvas 2D (no WebGL, no three.js): points sampled inside the
// logo's shield outline, spun in 3D with perspective. `scanning` adds a sweeping scan line that lights
// points up and speeds the spin. Pauses when hidden; static when the OS asks for reduced motion.
import { useEffect, useRef } from "react";

const SHIELD = "M32 12 48 18v13c0 10.5-6.8 18.6-16 21.9C22.8 49.6 16 41.5 16 31V18z";
const KEYHOLE = { cx: 32, cy: 29, r: 5, slot: [30, 32, 34, 41.5] };

function samplePoints(count) {
  const size = 256;
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = size;
  const ctx = canvas.getContext("2d");
  const scale = size / 64;
  const shield = new Path2D(SHIELD);
  const pts = [];
  let guard = 0;
  ctx.setTransform(scale, 0, 0, scale, 0, 0);
  while (pts.length < count && guard++ < count * 40) {
    const x = 16 + Math.random() * 32;
    const y = 12 + Math.random() * 41;
    if (!ctx.isPointInPath(shield, x * scale, y * scale)) continue;
    const inHole = Math.hypot(x - KEYHOLE.cx, y - KEYHOLE.cy) < KEYHOLE.r ||
      (y > KEYHOLE.slot[1] && y < KEYHOLE.slot[3] && Math.abs(x - 32) < 1.4 + (y - KEYHOLE.slot[1]) * 0.08);
    if (inHole) continue;
    // Edge points sit on a thin shell, inner points spread in depth: reads as a solid badge when turning.
    const depth = (Math.random() - 0.5) * 7;
    pts.push({ x: (x - 32) / 21, y: (y - 32.5) / 21, z: depth / 21, s: 0.7 + Math.random() * 0.9, p: Math.random() * Math.PI * 2 });
  }
  return pts;
}

export default function ShieldCanvas({ size = 360, scanning = false, count = 2400, className = "" }) {
  const ref = useRef(null);
  const scanRef = useRef(scanning);
  scanRef.current = scanning;

  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas.getContext("2d");
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    ctx.scale(dpr, dpr);
    const pts = samplePoints(count);
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const accent = getComputedStyle(document.documentElement).getPropertyValue("--accent").trim() || "#4a67ff";
    const glow = getComputedStyle(document.documentElement).getPropertyValue("--accent-2").trim() || "#8fa2ff";
    let angle = 0;
    let tilt = 0;
    let mouseX = 0;
    let mouseY = 0;
    let frame = 0;
    let last = performance.now();
    let sweep = -1.2;

    const onMove = (e) => {
      const rect = canvas.getBoundingClientRect();
      mouseX = ((e.clientX - rect.left) / rect.width - 0.5) * 2;
      mouseY = ((e.clientY - rect.top) / rect.height - 0.5) * 2;
    };
    window.addEventListener("pointermove", onMove);

    const draw = (now) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      const scan = scanRef.current;
      if (!reduced) {
        angle += dt * (scan ? 1.6 : 0.5);
        tilt += ((mouseY * 0.25) - tilt) * Math.min(1, dt * 3);
        sweep += dt * 1.1;
        if (sweep > 1.3) sweep = -1.3;
      }
      // Idle: a slow sway that keeps the shield readable; scanning: a full spin.
      const yaw = (scan ? angle : Math.sin(angle) * 0.6) + mouseX * 0.3;
      const cos = Math.cos(yaw);
      const sin = Math.sin(yaw);
      const ct = Math.cos(tilt);
      const st = Math.sin(tilt);
      ctx.clearRect(0, 0, size, size);
      const r = size * 0.42;
      const cx = size / 2;
      const cy = size / 2;
      for (const p of pts) {
        const x = p.x * cos + p.z * sin;
        let z = -p.x * sin + p.z * cos;
        const y = p.y * ct - z * st;
        z = p.y * st + z * ct;
        const persp = 1.6 / (1.6 + z);
        const px = cx + x * r * persp;
        const py = cy + y * r * persp;
        const near = scan ? Math.max(0, 1 - Math.abs(p.y - sweep) * 7) : 0;
        const twinkle = reduced ? 1 : 0.75 + 0.25 * Math.sin(now / 600 + p.p);
        const alpha = Math.min(1, (0.35 + (1 - (z + 0.5)) * 0.45) * twinkle + near);
        ctx.globalAlpha = alpha;
        ctx.fillStyle = near > 0.2 ? glow : accent;
        const rad = p.s * persp * (size / 360) * (1 + near * 1.2);
        ctx.beginPath();
        ctx.arc(px, py, rad, 0, Math.PI * 2);
        ctx.fill();
      }
      if (scan) {
        ctx.globalAlpha = 0.5;
        const ly = cy + sweep * r;
        const grad = ctx.createLinearGradient(0, ly - 18, 0, ly + 18);
        grad.addColorStop(0, "transparent");
        grad.addColorStop(0.5, glow);
        grad.addColorStop(1, "transparent");
        ctx.fillStyle = grad;
        ctx.fillRect(cx - r * 0.9, ly - 18, r * 1.8, 36);
      }
      ctx.globalAlpha = 1;
      if (!reduced && !document.hidden) frame = requestAnimationFrame(draw);
    };
    const onVisibility = () => {
      cancelAnimationFrame(frame);
      if (!document.hidden) {
        last = performance.now();
        frame = requestAnimationFrame(draw);
      }
    };
    document.addEventListener("visibilitychange", onVisibility);
    frame = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("pointermove", onMove);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [size, count]);

  return <canvas ref={ref} className={`shield-canvas ${className}`} style={{ width: size, height: size }} aria-hidden="true" />;
}
