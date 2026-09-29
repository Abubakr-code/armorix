import { useCallback, useState } from "react";
import { CheckCircle2, Info, XCircle } from "lucide-react";

let seq = 0;

export function useToasts() {
  const [items, setItems] = useState([]);
  const push = useCallback((text, tone = "ok", ms = 4200) => {
    const id = ++seq;
    setItems((cur) => [...cur.slice(-3), { id, text, tone }]);
    setTimeout(() => setItems((cur) => cur.filter((x) => x.id !== id)), ms);
  }, []);
  return { items, push };
}

export default function Toasts({ items }) {
  return (
    <div className="toasts" aria-live="polite">
      {items.map((x) => (
        <div key={x.id} className={`toast ${x.tone}`}>
          {x.tone === "error" ? <XCircle size={16} /> : x.tone === "info" ? <Info size={16} /> : <CheckCircle2 size={16} />}
          <span>{x.text}</span>
        </div>
      ))}
    </div>
  );
}
