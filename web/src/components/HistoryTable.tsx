import type { Analysis } from '../types'

interface Props {
  items: Analysis[]
  loading: boolean
}

export function HistoryTable({ items, loading }: Props) {
  return (
    <section className="panel">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Audit trail</p>
          <h2>Recent analyses</h2>
        </div>
      </div>
      {loading ? <p>Loading history…</p> : items.length === 0 ? <p className="muted">No analyses have been stored.</p> : (
        <div className="table-scroll">
          <table>
            <thead><tr><th>Time</th><th>URL</th><th>Classification</th><th>Probability</th></tr></thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.analysis_id}>
                  <td>{new Date(item.created_at).toLocaleString()}</td>
                  <td><code>{item.submitted_url}</code></td>
                  <td><span className={`status ${item.classification}`}>{item.classification}</span></td>
                  <td>{(item.malicious_probability * 100).toFixed(1)}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
