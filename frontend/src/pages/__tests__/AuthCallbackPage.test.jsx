import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router'
import { describe, expect, it, vi } from 'vitest'
import AuthCallbackPage from '../AuthCallbackPage'
import HomePage from '../../components/HomePage'

vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({ loginWithGitHub: vi.fn(), user: null }),
}))

function LocationProbe() {
  const location = useLocation()
  return <div data-testid="location">{location.pathname + location.search}</div>
}

describe('AuthCallbackPage', () => {
  it('sends successful callbacks to onboarding', async () => {
    render(
      <MemoryRouter initialEntries={['/auth/callback?code=123']}>
        <Routes>
          <Route path="/auth/callback" element={<AuthCallbackPage />} />
          <Route path="/dashboard/onboarding" element={<div>Onboarding Route</div>} />
        </Routes>
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('Onboarding Route')).toBeInTheDocument()
    })
  })

  it('returns to home with the error when the callback contains one', async () => {
    render(
      <MemoryRouter initialEntries={['/auth/callback?error=oauth_failed']}>
        <Routes>
          <Route path="/auth/callback" element={<AuthCallbackPage />} />
          <Route path="/dashboard/onboarding" element={<div>Onboarding Route</div>} />
          <Route path="/" element={<LocationProbe />} />
        </Routes>
      </MemoryRouter>
    )

    expect(await screen.findByTestId('location')).toHaveTextContent('/?error=oauth_failed')
    expect(screen.queryByText('Onboarding Route')).toBeNull()
  })

  it('URL-encodes the error on the way to the home page', async () => {
    render(
      <MemoryRouter initialEntries={['/auth/callback?error=access%20denied%26x%3D1']}>
        <Routes>
          <Route path="/auth/callback" element={<AuthCallbackPage />} />
          <Route path="/" element={<LocationProbe />} />
        </Routes>
      </MemoryRouter>
    )

    expect(await screen.findByTestId('location')).toHaveTextContent('/?error=access%20denied%26x%3D1')
  })

  it('ends on a home page that says sign-in failed for access_denied', async () => {
    render(
      <MemoryRouter initialEntries={['/auth/callback?error=access_denied']}>
        <Routes>
          <Route path="/auth/callback" element={<AuthCallbackPage />} />
          <Route path="/" element={<HomePage />} />
        </Routes>
      </MemoryRouter>
    )

    expect(await screen.findByRole('alert')).toHaveTextContent('Sign-in failed')
  })
})
