import { useForm } from 'react-hook-form'
import { urlSchema } from '../urlValidation'

interface FormValues {
  url: string
}

interface Props {
  busy: boolean
  onAnalyze: (url: string) => void
}

export function AnalysisForm({ busy, onAnalyze }: Props) {
  const {
    register,
    handleSubmit,
    setError,
    formState: { errors },
  } = useForm<FormValues>({ defaultValues: { url: '' } })

  const submit = ({ url }: FormValues) => {
    const result = urlSchema.safeParse(url)
    if (!result.success) {
      setError('url', { message: result.error.issues[0]?.message ?? 'Invalid URL.' })
      return
    }
    onAnalyze(result.data)
  }

  return (
    <form className="analysis-form" onSubmit={(event) => void handleSubmit(submit)(event)} noValidate>
      <label htmlFor="url">URL to analyze</label>
      <div className="input-row">
        <input
          id="url"
          type="text"
          inputMode="url"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          aria-invalid={Boolean(errors.url)}
          aria-describedby={errors.url ? 'url-error' : 'url-help'}
          placeholder="https://example.test/account/verify"
          {...register('url')}
        />
        <button type="submit" disabled={busy}>{busy ? 'Analyzing…' : 'Analyze'}</button>
      </div>
      {errors.url ? <p id="url-error" className="error">{errors.url.message}</p> : null}
      <p id="url-help" className="muted">Lexical analysis only. The application does not visit the submitted address.</p>
    </form>
  )
}
