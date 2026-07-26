/** Partially mask secret-shaped evidence before returning it to agents/logs. */
export function redactedEvidence(raw: string): string {
  if (raw.length <= 24) return raw.replace(/[A-Za-z0-9]/g, (ch, i) => (i < 4 ? ch : "*"));
  return raw.slice(0, 8) + "…" + raw.slice(-4).replace(/./g, "*") + ` (len=${raw.length})`;
}
