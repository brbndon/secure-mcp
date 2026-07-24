export default function Page() {
  const html = "<img src=x onerror=alert(1)>";
  return (
    <main>
      <div dangerouslySetInnerHTML={{ __html: html }} />
    </main>
  );
}
