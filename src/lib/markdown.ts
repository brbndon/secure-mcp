/** Escape untrusted values before placing them in Markdown text output. */
export function escapeMarkdown(value: string): string {
  return value
    .replace(/\r\n?|\n/g, " ")
    .replace(/([\\`*_{}\[\]()#+.!|<>~=\-:\/@&$%^?'",;])/g, "\\$1");
}

/** Render untrusted evidence as a bounded inline code value. */
export function markdownCode(value: string): string {
  return `\`${value.replace(/\r\n?|\n/g, "\\n").replace(/`/g, "\\u0060")}\``;
}
