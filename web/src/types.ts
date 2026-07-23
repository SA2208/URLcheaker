export type Classification = 'malicious' | 'benign' | 'uncertain'

export interface Reason {
  code: string
  description: string
  feature_name: string
  feature_value: number
}

export interface FeedMatch {
  source_name: string
  source_record_id: string
  threat_type: string
  first_seen: string | null
  last_seen: string | null
}

export interface Analysis {
  analysis_id: string
  submitted_url: string
  classification: Classification
  threat_type: string | null
  malicious_probability: number
  confidence: 'high' | 'medium' | 'low'
  decision_source: 'threat_feed' | 'machine_learning' | 'combined'
  reasons: Reason[]
  feed_matches: FeedMatch[]
  requires_analyst_review: boolean
  model_version: string
  dataset_version: string
  model_backend: string
  created_at: string
}

export interface AnalysisList {
  items: Analysis[]
  page: number
  page_size: number
  total: number
}


export interface DashboardSummary {
  total: number
  malicious: number
  benign: number
  uncertain: number
  requires_review: number
  threat_feed_decisions: number
}
