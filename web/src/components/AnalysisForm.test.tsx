import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { AnalysisForm } from './AnalysisForm'

describe('AnalysisForm', () => {
  it('rejects unsupported schemes', async () => {
    const user = userEvent.setup()
    const onAnalyze = vi.fn()
    render(<AnalysisForm busy={false} onAnalyze={onAnalyze} />)
    await user.type(screen.getByLabelText(/url to analyze/i), 'javascript:alert(1)')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(await screen.findByText(/only http and https/i)).toBeInTheDocument()
    expect(onAnalyze).not.toHaveBeenCalled()
  })

  it('submits an HTTPS URL', async () => {
    const user = userEvent.setup()
    const onAnalyze = vi.fn()
    render(<AnalysisForm busy={false} onAnalyze={onAnalyze} />)
    await user.type(screen.getByLabelText(/url to analyze/i), 'https://example.test/path')
    await user.click(screen.getByRole('button', { name: 'Analyze' }))
    expect(onAnalyze).toHaveBeenCalledWith('https://example.test/path')
  })
})
