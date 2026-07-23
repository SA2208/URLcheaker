import type { DashboardSummary } from '../types'

interface Props {
  summary?: DashboardSummary
}

export function SummaryCards({ summary }: Props) {
  const values = [
    ['Total', summary?.total ?? 0],
    ['Malicious', summary?.malicious ?? 0],
    ['Benign', summary?.benign ?? 0],
    ['Uncertain', summary?.uncertain ?? 0],
    ['Review queue', summary?.requires_review ?? 0],
    ['Feed decisions', summary?.threat_feed_decisions ?? 0],
  ] as const

  return (
    <section className="summary-grid" aria-label="Analysis summary">
      {values.map(([label, value]) => (
        <div className="summary-card" key={label}>
          <span>{label}</span>
          <strong>{value}</strong>
        </div>
      ))}
    </section>
  )
}
