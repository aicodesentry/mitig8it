import { useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router'

const AuthCallbackPage = () => {
  const navigate = useNavigate()
  const { search } = useLocation()

  useEffect(() => {
    const finishCallback = async () => {
      const params = new URLSearchParams(search)
      const error = params.get('error')

      if (error) {
        navigate(`/?error=${encodeURIComponent(error)}`, { replace: true })
        return
      }

      try {
        navigate('/dashboard/onboarding', { replace: true })
      } catch (_err) {
        navigate('/')
      }
    }

    finishCallback()
  }, [navigate, search])

  return (
    <div className="min-h-screen flex items-center justify-center bg-neutral-950">
      <div className="text-neutral-400 text-sm">Signing in...</div>
    </div>
  )
}

export default AuthCallbackPage
