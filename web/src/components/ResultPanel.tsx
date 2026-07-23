import type { Analysis } from '../types'


function exportAnalysis(analysis: Analysis) {
  const blob = new Blob([JSON.stringify(analysis, null, 2)], { type: 'application/json' })
  const objectUrl = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = objectUrl
  anchor.download = `urlchecker-${analysis.analysis_id}.json`
  anchor.click()
  URL.revokeObjectURL(objectUrl)
}

interface Props {
  analysis: Analysis
  verdictPending: boolean
  onVerdict: (verdict: 'confirmed_malicious' | 'confirmed_benign' | 'needs_more_analysis') => void
}

export function ResultPanel({ analysis, verdictPending, onVerdict }: Props) {
  const probability = `${(analysis.malicious_probability * 100).toFixed(2)}%`
  return (
    <section className="panel result-panel" aria-live="polite">
      <div className="result-heading">
        <div>
          <p className="eyebrow">Classification</p>
          <h2 className={`classification ${analysis.classification}`}>{analysis.classification}</h2>
        </div>
        <div className="score" aria-label={`Malicious probability ${probability}`}>
          <strong>{probability}</strong>
          <span>malicious probability</span>
        </div>
      </div>

      <dl className="metadata-grid">
        <div><dt>Confidence</dt><dd>{analysis.confidence}</dd></div>
        <div><dt>Decision source</dt><dd>{analysis.decision_source.replace('_', ' ')}</dd></div>
        <div><dt>Threat type</dt><dd>{analysis.threat_type ?? 'Not assigned'}</dd></div>
        <div><dt>Review required</dt><dd>{analysis.requires_analyst_review ? 'Yes' : 'No'}</dd></div>
      </dl>

      <div className="safe-url">
        <h3>Stored URL representation</h3>
        <code>{analysis.submitted_url}</code>
        <div className="button-row">
          <button type="button" className="secondary" onClick={() => void navigator.clipboard.writeText(analysis.submitted_url)}>Copy text</button>
          <button type="button" className="secondary" onClick={() => exportAnalysis(analysis)}>Export JSON</button>
        </div>
      </div>

      <div>
        <h3>Observed indicators</h3>
        {analysis.reasons.length ? (
          <ul className="reasons">
            {analysis.reasons.map((reason) => (
              <li key={`${reason.code}-${reason.feature_name}`}>
                <strong>{reason.code.replaceAll('_', ' ')}</strong>
                <span>{reason.description}</span>
              </li>
            ))}
          </ul>
        ) : <p className="muted">No high-risk lexical indicators crossed the display thresholds.</p>}
      </div>

      {analysis.feed_matches.length ? (
        <div>
          <h3>Threat-feed evidence</h3>
          <ul className="feed-list">
            {analysis.feed_matches.map((match) => (
              <li key={`${match.source_name}-${match.source_record_id}`}>
                {match.source_name} · {match.threat_type} · record {match.source_record_id}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="verdicts">
        <h3>Analyst verdict</h3>
        <button disabled={verdictPending} onClick={() => onVerdict('confirmed_malicious')}>Confirm malicious</button>
        <button disabled={verdictPending} onClick={() => onVerdict('confirmed_benign')}>Confirm benign</button>
        <button disabled={verdictPending} className="secondary" onClick={() => onVerdict('needs_more_analysis')}>Needs analysis</button>
      </div>

      <footer className="result-footer">
        Model {analysis.model_version} · Dataset {analysis.dataset_version} · Backend {analysis.model_backend}
      </footer>
    </section>
  )
}
