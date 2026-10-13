import DOMPurify from "dompurify";
import { useEffect, useState } from "react";
export function Safe({html}: {html: string}) {
  const [clean, setClean] = useState({source: "", html: ""});
  useEffect(() => { setClean({source: html, html: DOMPurify.sanitize(html)}); }, [html]);
  return <div dangerouslySetInnerHTML={{__html: clean.source === html ? clean.html : ""}} />;
}
