import React, { useEffect, useMemo, useState } from 'react'

import {
  getActiveApiKey,
  getActiveApiKeyMask,
  getHealth,
  getModelInfo,
  getScenarios,
  getStreamStats,
  listApiKeys,
  setActiveApiKey,
} from './api/client'
import { connectLiveStream } from './lib/ws'

import BatchUpload from './views/BatchUpload'
import DeveloperPortal from './views/DeveloperPortal'
import LandingPage from './views/LandingPage'
import LiveFeed from './views/LiveFeed'
import ManualAnalysis from './views/ManualAnalysis'
import ModelInsights from './views/ModelInsights'
import PipelineWalkthrough from './views/PipelineWalkthrough'

const VIEWS = [
  { id: 'live', label: 'Live Feed' },
  { id: 'manual', label: 'Manual Analysis' },
  { id: 'batch', label: 'Batch / CSV' },
  { id: 'insights', label: 'Model Insights' },
  { id: 'pipeline', label: 'Pipeline Walkthrough' },
  { id: 'portal', label: 'Developer Portal' },
]

function healthLabel(status) {
  const ok = status === 'ok'
  return ok ? 'API ONLINE' : 'API OFFLINE'
}

function maskRawKey(raw) {
  if (!raw || raw.length < 8) return 'none'
  return `mw_live_sk_....${raw.slice(-4)}`
}

export default function App() {
  const [route, setRoute] = useState(() => window.location.pathname)
  const [activeView, setActiveView] = useState('live')
  const [modelInfo, setModelInfo] = useState(null)
  const [health, setHealth] = useState('loading')
  const [streamStats, setStreamStats] = useState({})
  const [streamState, setStreamState] = useState('disconnected')
  const [events, setEvents] = useState([])
  const [scenarios, setScenarios] = useState([])
  const [activeKey, setActiveKey] = useState(getActiveApiKey())
  const [activeMask, setActiveMask] = useState(getActiveApiKeyMask())
  const [keys, setKeys] = useState([])

  function clearActiveKeySession() {
    setActiveApiKey('', '')
    setActiveKey('')
    setActiveMask('')
    setStreamState('disconnected')
  }

  function isAuthError(err) {
    const message = (err?.message || '').toLowerCase()
    return (
      message.includes('unauthorized') ||
      message.includes('invalid') ||
      message.includes('revoked') ||
      message.includes('missing')
    )
  }

  useEffect(() => {
    const onPopState = () => setRoute(window.location.pathname)
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  function navigate(nextPath) {
    if (nextPath === window.location.pathname) return
    window.history.pushState({}, '', nextPath)
    setRoute(nextPath)
  }

  const isLandingPage = route === '/'

  useEffect(() => {
    if (isLandingPage) return
    getModelInfo().then(setModelInfo).catch(() => {})
  }, [isLandingPage])

  useEffect(() => {
    if (isLandingPage) return
    const pollHealth = () => {
      getHealth()
        .then((res) => setHealth(res.status || 'offline'))
        .catch(() => setHealth('offline'))
    }
    pollHealth()
    const timer = window.setInterval(pollHealth, 4000)
    return () => window.clearInterval(timer)
  }, [isLandingPage])

  useEffect(() => {
    if (isLandingPage) return
    if (!activeKey) return

    const pollStats = () => {
      getStreamStats()
        .then((stats) => setStreamStats(stats))
        .catch((err) => {
          if (isAuthError(err)) {
            clearActiveKeySession()
          }
        })
    }

    const pollScenarios = () => {
      getScenarios()
        .then((res) => setScenarios(res.scenarios || []))
        .catch((err) => {
          if (isAuthError(err)) {
            clearActiveKeySession()
          }
        })
    }

    pollStats()
    pollScenarios()

    const statsTimer = window.setInterval(pollStats, 3500)
    const scenarioTimer = window.setInterval(pollScenarios, 15000)
    return () => {
      window.clearInterval(statsTimer)
      window.clearInterval(scenarioTimer)
    }
  }, [activeKey, isLandingPage])

  useEffect(() => {
    if (isLandingPage) return
    listApiKeys()
      .then((res) => {
        const available = res.keys || []
        setKeys(available)
        if (!activeKey && available[0]?.is_active) {
          const fallbackMask = available[0].masked_key
          setActiveMask(fallbackMask)
        }
      })
      .catch(() => {})
  }, [activeKey, isLandingPage])

  useEffect(() => {
    if (isLandingPage) return
    const disconnect = connectLiveStream({
      apiKey: activeKey,
      onState: setStreamState,
      onBackfill: (history) => {
        setEvents((_) => (Array.isArray(history) ? [...history].reverse() : []))
      },
      onEvent: (event) => {
        setEvents((prev) => [event, ...prev].slice(0, 200))
      },
    })

    return disconnect
  }, [activeKey, isLandingPage])

  const counters = useMemo(() => {
    const e60 = streamStats.events_last_60s ?? 0
    const malwareRate = streamStats.malware_rate ?? 0
    return {
      eventsPerMin: e60,
      malwareRate,
      clients: streamStats.connected_clients ?? 0,
    }
  }, [streamStats])

  function handleScenarioInjected() {
    getStreamStats()
      .then((stats) => setStreamStats(stats))
      .catch((err) => {
        if (isAuthError(err)) {
          clearActiveKeySession()
        }
      })
  }

  function handleKeySwitch(value) {
    if (!value) {
      clearActiveKeySession()
      return
    }
    const keyItem = keys.find((k) => k.key_id === value)
    if (!keyItem) return
    const raw = window.prompt('Paste raw API key for this selection:') || ''
    if (!raw) return
    setActiveApiKey(raw, keyItem.masked_key)
    setActiveKey(raw)
    setActiveMask(keyItem.masked_key)
  }

  let content = <div className="text-slate-300">Loading model metadata...</div>

  if (activeView === 'live') {
    content = (
      <LiveFeed
        events={events}
        streamState={streamState}
        scenarios={scenarios}
        onScenarioInjected={handleScenarioInjected}
        streamStats={streamStats}
      />
    )
  }
  if (activeView === 'manual') {
    content = <ManualAnalysis modelInfo={modelInfo} recentEvents={events} />
  }
  if (activeView === 'batch') {
    content = <BatchUpload modelInfo={modelInfo} />
  }
  if (activeView === 'insights') {
    content = <ModelInsights modelInfo={modelInfo} />
  }
  if (activeView === 'pipeline') {
    content = <PipelineWalkthrough modelInfo={modelInfo} />
  }
  if (activeView === 'portal') {
    content = (
      <DeveloperPortal
        onKeyChanged={(rawKey) => {
          setActiveKey(rawKey)
          setActiveMask(maskRawKey(rawKey))
        }}
      />
    )
  }

  if (isLandingPage) {
    return <LandingPage onEnterDashboard={() => navigate('/dashboard')} />
  }

  return (
    <div className="min-h-screen bg-app text-slate-100">
      <header className="sticky top-0 z-40 border-b border-cyan-950 backdrop-blur bg-[#070b11]/90">
        <div className="px-4 py-3 flex flex-wrap gap-3 items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 rounded border border-cyan-700 grid place-items-center text-[10px] tracking-[0.22em] text-cyan-300 font-bold">SIO</div>
            <div>
              <div className="text-sm tracking-[0.25em] uppercase text-cyan-300">SentinelIOC</div>
              <div className="text-xs text-slate-400">Live threat simulation and IOC detection control plane</div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className={`px-2 py-1 border rounded ${health === 'ok' ? 'border-emerald-700 text-emerald-300' : 'border-rose-700 text-rose-300'}`}>
              {healthLabel(health)}
            </span>
            <span className="px-2 py-1 border border-slate-800 rounded text-cyan-200">events/min: {counters.eventsPerMin}</span>
            <span className="px-2 py-1 border border-slate-800 rounded text-rose-200">malware rate: {counters.malwareRate}%</span>
            <span className="px-2 py-1 border border-slate-800 rounded animate-pulse">LIVE {counters.clients}</span>
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400">Active key:</span>
            <span className="font-mono text-cyan-200">{activeMask || 'none'}</span>
            <select
              className="bg-slate-900 border border-slate-800 rounded px-2 py-1"
              value=""
              onChange={(e) => handleKeySwitch(e.target.value)}
            >
              <option value="">Switch key</option>
              {keys.map((key) => (
                <option key={key.key_id} value={key.key_id}>
                  {key.label} ({key.masked_key})
                </option>
              ))}
            </select>
            <button className="border border-cyan-700 px-2 py-1 rounded" onClick={() => setActiveView('portal')}>
              Key Manager
            </button>
            <button className="border border-slate-700 px-2 py-1 rounded" onClick={() => navigate('/')}>
              Landing
            </button>
          </div>
        </div>

        <nav className="px-4 border-t border-cyan-950 flex gap-1 overflow-x-auto">
          {VIEWS.map((view) => (
            <button
              key={view.id}
              className={`px-3 py-2 text-xs uppercase tracking-wide border-b-2 ${
                activeView === view.id
                  ? 'border-cyan-300 text-cyan-200'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
              onClick={() => setActiveView(view.id)}
            >
              {view.label}
            </button>
          ))}
        </nav>
      </header>

      <main className="p-4">{content}</main>
    </div>
  )
}
