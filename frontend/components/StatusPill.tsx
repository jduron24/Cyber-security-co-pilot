export function StatusPill({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode;
  tone?: "critical" | "warning" | "safe" | "neutral";
}) {
  return <span className={`status-pill status-pill--${tone}`}>{children}</span>;
}
