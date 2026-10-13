import DOMPurify from "dompurify";
export function Safe({html}: {html: string}) {
  return <div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(html)}} />;
}
