import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { analyzeUrl, getDashboardSummary, listAnalyses, submitVerdict } from './api'
import { AnalysisForm } from './components/AnalysisForm'
import { HistoryTable } from './components/HistoryTable'
import { ResultPanel } from './components/ResultPanel'
import { SummaryCards } from './components/SummaryCards'
import './styles.css'

export default function App() {
  const queryClient = useQueryClient()
  const analysisMutation = useMutation({
    mutationFn: analyzeUrl,
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['analyses'] })
      void queryClient.invalidateQueries({ queryKey: ['summary'] })
    },
  })
  const history = useQuery({ queryKey: ['analyses'], queryFn: () => listAnalyses() })
  const summary = useQuery({ queryKey: ['summary'], queryFn: getDashboardSummary })
  const verdictMutation = useMutation({
    mutationFn: ({ id, verdict }: { id: string; verdict: 'confirmed_malicious' | 'confirmed_benign' | 'needs_more_analysis' }) => submitVerdict(id, verdict),
  })

  return (
    <div className="app-shell">
      <header className="site-header">
        <div>
          <p className="product-mark">URLCHEAKER</p>
          <h1>Malicious URL triage for SOC workflows</h1>
          <p className="subtitle">Threat-feed matching and interpretable lexical analysis with an explicit uncertainty state.</p>
        </div>
        <div className="header-badge">NO-FETCH MODE</div>
      </header>

      <main>
        <SummaryCards summary={summary.data} />
        <section className="panel analyze-panel">
          <p className="eyebrow">New analysis</p>
          <h2>Inspect a URL safely</h2>
          <AnalysisForm busy={analysisMutation.isPending} onAnalyze={(url) => analysisMutation.mutate(url)} />
          {analysisMutation.isError ? <p className="error" role="alert">{analysisMutation.error.message}</p> : null}
        </section>

        {analysisMutation.data ? (
          <ResultPanel
            analysis={analysisMutation.data}
            verdictPending={verdictMutation.isPending}
            onVerdict={(verdict) => verdictMutation.mutate({ id: analysisMutation.data.analysis_id, verdict })}
          />
        ) : null}

        <HistoryTable items={history.data?.items ?? []} loading={history.isLoading} />
      </main>

      <footer className="site-footer">Decision support only. A benign classification is not proof that a destination is safe.</footer>
    </div>
  )
}
