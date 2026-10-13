export function Unsafe({unsanitized}: {unsanitized: string}) {
  return <div dangerouslySetInnerHTML={{__html: unsanitized}} />;
}
