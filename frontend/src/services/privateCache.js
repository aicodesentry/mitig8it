let epoch = 0
export const getPrivateCacheEpoch = () => epoch

export const clearPrivateCaches = () => {
  epoch += 1
  try {
    for (const key of Object.keys(window.localStorage)) {
      if (key.startsWith('reports_cache_')) window.localStorage.removeItem(key)
    }
  } catch (_error) { /* Storage can be disabled. */ }
}
