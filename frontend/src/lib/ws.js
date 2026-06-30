export function buildStreamUrl(apiKey) {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  const encoded = encodeURIComponent(apiKey || '')
  return `${protocol}//${host}/api/ws/stream?api_key=${encoded}`
}

export function connectLiveStream({ apiKey, onEvent, onBackfill, onState }) {
  if (!apiKey) {
    onState?.('missing_key')
    return () => {}
  }

  let ws
  let closedManually = false
  let retryTimer = null
  let attempt = 0

  const openSocket = () => {
    if (closedManually) return

    ws = new WebSocket(buildStreamUrl(apiKey))
    onState?.('connecting')

    ws.onopen = () => {
      attempt = 0
      onState?.('connected')
      ws.send('ping')
    }

    ws.onmessage = (message) => {
      try {
        const payload = JSON.parse(message.data)
        if (payload?.type === 'backfill') {
          onBackfill?.(payload.data || [])
          return
        }
        if (payload?.type === 'event' && payload?.data) {
          onEvent?.(payload.data)
          ws.send('ping')
        }
      } catch {
        // Ignore malformed frame.
      }
    }

    ws.onerror = () => {
      onState?.('error')
    }

    ws.onclose = () => {
      onState?.('disconnected')
      if (closedManually) return
      const backoffMs = Math.min(5000, 600 + attempt * 600)
      attempt += 1
      retryTimer = window.setTimeout(openSocket, backoffMs)
    }
  }

  openSocket()

  return () => {
    closedManually = true
    if (retryTimer) {
      window.clearTimeout(retryTimer)
    }
    if (ws && ws.readyState <= 1) {
      ws.close(1000, 'client disconnect')
    }
  }
}
