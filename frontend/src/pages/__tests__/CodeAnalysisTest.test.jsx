import { fireEvent, render, screen } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import CodeAnalysisTest from '../CodeAnalysisTest'
import { analysisAPI } from '../../services/api'
vi.mock('../../services/api', () => ({ analysisAPI: { healthCheck: vi.fn(), getHistory: vi.fn(), analyzeCode: vi.fn() } }))
beforeEach(() => {
  localStorage.clear(); vi.clearAllMocks()
  analysisAPI.healthCheck.mockResolvedValue({ status: 'ok', remaining_uses: 4 })
  analysisAPI.getHistory.mockResolvedValue({ analyses: [] })
})
it('uses the server quota and displays authenticated analysis results', async () => {
  localStorage.setItem('code_analysis_usage', JSON.stringify({ date: new Date().toDateString(), count: 5 }))
  analysisAPI.analyzeCode.mockResolvedValue({ analysis_id: 'fixture', remaining_uses: 3, vulnerabilities: [{ type: 'eval', severity: 'critical', line_number: 1, confidence: 1, description: 'Unsafe eval', recommendation: 'Parse safely' }], total_vulnerabilities: 1, critical_count: 1 })
  render(<CodeAnalysisTest />)
  await screen.findByText(/4\/5 analyses left/)
  fireEvent.change(screen.getByPlaceholderText('Paste your code here...'), { target: { value: 'eval(input())' } })
  fireEvent.click(screen.getByRole('button', { name: 'Analyze Code' }))
  expect(await screen.findByText('Unsafe eval', { exact: false })).toBeInTheDocument()
  expect(screen.getByText(/3\/5 analyses left/)).toBeInTheDocument()
})
it('shows server quota errors and prevents another submission', async () => {
  analysisAPI.analyzeCode.mockRejectedValue({ response: { data: { error: 'Daily limit reached', remaining_uses: 0 } } })
  render(<CodeAnalysisTest />)
  await screen.findByText('Service Online')
  fireEvent.change(screen.getByPlaceholderText('Paste your code here...'), { target: { value: 'eval(input())' } })
  fireEvent.click(screen.getByRole('button', { name: 'Analyze Code' }))
  expect(await screen.findByText('Daily limit reached')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Analyze Code' })).toBeDisabled()
})
