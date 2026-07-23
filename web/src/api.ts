import type { Analysis, AnalysisList, DashboardSummary } from './types'

const API_BASE = import.meta.env.VITE_API_URL ?? ''

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message)
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...init?.headers,
    },
    credentials: 'omit',
  })
  const body = (await response.json().catch(() => null)) as { detail?: string } | null
  if (!response.ok) {
    throw new ApiError(body?.detail ?? 'The service returned an unexpected error.', response.status)
  }
  return body as T
}

export function analyzeUrl(url: string): Promise<Analysis> {
  return request('/api/v1/analyses', {
    method: 'POST',
    body: JSON.stringify({ url }),
  })
}

export function listAnalyses(classification = ''): Promise<AnalysisList> {
  const query = classification ? `?classification=${encodeURIComponent(classification)}` : ''
  return request(`/api/v1/analyses${query}`)
}

export function submitVerdict(
  analysisId: string,
  verdict: 'confirmed_malicious' | 'confirmed_benign' | 'needs_more_analysis',
): Promise<unknown> {
  return request(`/api/v1/analyses/${encodeURIComponent(analysisId)}/verdicts`, {
    method: 'POST',
    body: JSON.stringify({ verdict }),
  })
}


export function getDashboardSummary(): Promise<DashboardSummary> {
  return request('/api/v1/dashboard/summary')
}
