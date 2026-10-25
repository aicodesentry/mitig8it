import { useEffect, useState } from 'react'
import { installationAPI } from '../services/api'

export default function SettingsPage() {
  const [installations, setInstallations] = useState([])
  const [syncResult, setSyncResult] = useState(null)
  const [loaded, setLoaded] = useState(false)
  const [error, setError] = useState('')

  const load = async () => {
    try {
      const data = await installationAPI.list()
      setInstallations(data.installations || [])
      setLoaded(true)
    } catch (_failure) {
      setError('Could not load installations. Refresh to try again.')
    }
  }

  useEffect(() => {
    load()
  }, [])

  const sync = async () => {
    setError('')
    let result
    try {
      result = await installationAPI.sync()
    } catch (_failure) {
      setError('Could not sync installations from GitHub. Try again in a moment.')
      return
    }
    setSyncResult(result)
    await load()
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold text-neutral-900">Settings</h1>

      <div className="rounded-xl border border-neutral-200 bg-white p-6">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-neutral-900">GitHub App Installations</h2>
            <p className="text-sm text-neutral-500">Sync installation metadata from GitHub App API.</p>
          </div>
          <button onClick={sync} className="rounded-lg bg-neutral-900 px-4 py-2 text-sm font-semibold text-white">Sync now</button>
        </div>

        {error && <p role="alert" className="mt-3 text-sm text-red-700">{error}</p>}

        {syncResult && (
          <p className="mt-3 text-sm text-neutral-600">Synced installations: {syncResult.synced_installations}</p>
        )}

        <div className="mt-4 space-y-2">
          {!loaded && !error && <p role="status" className="text-sm text-neutral-500">Loading installations...</p>}
          {loaded && !error && installations.length === 0 && <p className="text-sm text-neutral-500">No installations found.</p>}
          {installations.map((installation) => (
            <div key={installation.id} className="rounded-lg border border-neutral-200 px-4 py-3">
              <p className="font-medium text-neutral-900">{installation.account_login}</p>
              <p className="text-xs text-neutral-500">{installation.account_type} • {installation.status}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
