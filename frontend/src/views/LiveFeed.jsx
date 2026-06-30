import React, { useMemo, useState } from 'react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import { injectScenario } from '../api/client'
import ConfidenceBar from '../components/shared/ConfidenceBar'
import VerdictBadge from '../components/shared/VerdictBadge'

const IOC_ICON = {
  ip: 'IP',
  domain: 'DM',
  url: 'URL',
  hash: 'HSH',
}

function timeLabel(iso) {
  try {
    return new Date(iso).toLocaleTimeString()
  } catch {
    return '--:--:--'
  }
}

export default function LiveFeed({
  events,
  streamState,
  scenarios,
  onScenarioInjected,
  streamStats,
}) {
  const [expanded, setExpanded] = useState({})
  const [injecting, setInjecting] = useState('')
  const [pauseScroll, setPauseScroll] = useState(false)
  const [injectError, setInjectError] = useState('')

  const chartData = useMemo(() => {
    const sample = events.slice(0, 80).reverse()
    const bins = {}
    sample.forEach((event) => {
      const bucket = timeLabel(event.timestamp).slice(0, 5)
      if (!bins[bucket]) {
        bins[bucket] = { t: bucket, malware: 0, benign: 0 }
      }
      if (event.prediction === 'malware') bins[bucket].malware += 1
      else bins[bucket].benign += 1
    })
    return Object.values(bins).slice(-12)
  }, [events])

  const orderedEvents = events

  async function triggerScenario(scenarioId) {
    setInjectError('')
    setInjecting(scenarioId)
    try {
      const resp = await injectScenario(scenarioId)
      onScenarioInjected?.(resp)
    } catch (error) {
      setInjectError(error.message)
    } finally {
      setInjecting('')
    }
  }

  return (
    <div className="grid grid-cols-1 xl:grid-cols-[2.4fr_1fr] gap-4 h-[calc(100vh-185px)] min-h-[650px]">
      <section className="border border-cyan-950/80 bg-slate-950/70 rounded-lg overflow-hidden flex flex-col">
        <div className="px-4 py-3 border-b border-cyan-950 flex items-center justify-between">
          <div>
            <h2 className="text-sm tracking-[0.18em] text-cyan-300 uppercase">Live Traffic Feed</h2>
            <p className="text-xs text-slate-400">Stream status: {streamState}</p>
          </div>
          <button
            className="text-xs border border-cyan-800 px-2 py-1 rounded hover:bg-cyan-950/40"
            onMouseEnter={() => setPauseScroll(true)}
            onMouseLeave={() => setPauseScroll(false)}
          >
            {pauseScroll ? 'Scroll Paused' : 'Hover To Pause'}
          </button>
        </div>

        <div className="px-4 py-2 text-xs text-slate-300 border-b border-cyan-950 grid grid-cols-12 gap-2 uppercase tracking-wider">
          <span className="col-span-2">Time</span>
          <span className="col-span-1">Type</span>
          <span className="col-span-1">Country</span>
          <span className="col-span-2">Threat</span>
          <span className="col-span-2">Verdict</span>
          <span className="col-span-1">Conf</span>
          <span className="col-span-1">Port</span>
          <span className="col-span-2">Flags</span>
        </div>

        <div className="overflow-auto flex-1 feed-scroll" style={{ scrollBehavior: pauseScroll ? 'auto' : 'smooth' }}>
          {orderedEvents.map((event) => {
            const isOpen = !!expanded[event.event_id]
            return (
              <div
                key={event.event_id}
                className={`border-b border-slate-900 px-4 py-2 text-xs transition-all ${
                  event.is_injected
                    ? 'bg-rose-950/20 border-l-2 border-l-rose-500'
                    : 'hover:bg-cyan-950/15 border-l-2 border-l-transparent'
                }`}
              >
                <button
                  className="w-full text-left grid grid-cols-12 gap-2 items-center"
                  onClick={() => setExpanded((s) => ({ ...s, [event.event_id]: !s[event.event_id] }))}
                >
                  <span className="col-span-2 font-mono text-slate-300">{timeLabel(event.timestamp)}</span>
                  <span className="col-span-1 text-cyan-300 font-mono">{IOC_ICON[event.raw_record?.ioc_type] || 'IOC'}</span>
                  <span className="col-span-1 font-mono text-slate-300">{event.raw_record?.src_country}</span>
                  <span className="col-span-2 text-slate-300">{event.raw_record?.threat_type}</span>
                  <span className="col-span-2">
                    <VerdictBadge prediction={event.prediction} size="sm" />
                  </span>
                  <span className="col-span-1 font-mono text-slate-200">{(event.confidence * 100).toFixed(1)}%</span>
                  <span className="col-span-1 font-mono text-slate-200">{event.raw_record?.dst_port}</span>
                  <span className="col-span-2 font-mono text-[10px] text-slate-400">
                    {event.is_injected ? 'INJECTED' : 'AMBIENT'}
                    {event.scenario_id ? ` / ${event.scenario_id}` : ''}
                  </span>
                </button>

                {isOpen && (
                  <div className="mt-2 p-3 border border-cyan-950 rounded bg-slate-950/90 space-y-2">
                    <ConfidenceBar probabilities={event.all_probabilities} />
                    <pre className="text-[11px] text-slate-300 font-mono overflow-auto">{JSON.stringify(event.raw_record, null, 2)}</pre>
                  </div>
                )}
              </div>
            )
          })}
          {orderedEvents.length === 0 && (
            <div className="p-6 text-center text-slate-400">No events yet. Connect with an active API key.</div>
          )}
        </div>
      </section>

      <aside className="grid grid-rows-[auto_auto_1fr] gap-4">
        <section className="border border-cyan-950/80 bg-slate-950/70 rounded-lg p-4">
          <h3 className="text-xs uppercase tracking-[0.2em] text-cyan-300 mb-3">Scenario Injector</h3>
          <div className="space-y-2">
            {scenarios.map((scenario) => (
              <button
                key={scenario.scenario}
                disabled={!!injecting}
                className="w-full text-left border border-slate-800 hover:border-cyan-700 rounded px-3 py-2 text-xs disabled:opacity-40"
                onClick={() => triggerScenario(scenario.scenario)}
              >
                <div className="font-semibold text-slate-100">Inject {scenario.scenario}</div>
                <div className="text-slate-400">{scenario.description}</div>
                {injecting === scenario.scenario && (
                  <div className="mt-1 text-cyan-300">injecting...</div>
                )}
              </button>
            ))}
          </div>
          {injectError && <p className="text-rose-400 text-xs mt-2">{injectError}</p>}
        </section>

        <section className="border border-cyan-950/80 bg-slate-950/70 rounded-lg p-4">
          <h3 className="text-xs uppercase tracking-[0.2em] text-cyan-300 mb-2">Live Strip</h3>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="border border-slate-800 rounded p-2">
              <div className="text-slate-400">Events/60s</div>
              <div className="text-cyan-200 font-mono text-lg">{streamStats.events_last_60s ?? 0}</div>
            </div>
            <div className="border border-slate-800 rounded p-2">
              <div className="text-slate-400">Malware rate</div>
              <div className="text-rose-300 font-mono text-lg">{streamStats.malware_rate ?? 0}%</div>
            </div>
          </div>
        </section>

        <section className="border border-cyan-950/80 bg-slate-950/70 rounded-lg p-4">
          <h3 className="text-xs uppercase tracking-[0.2em] text-cyan-300 mb-2">Malware vs Benign</h3>
          <div className="h-full min-h-[220px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData}>
                <defs>
                  <linearGradient id="mgrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.8} />
                    <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.08} />
                  </linearGradient>
                  <linearGradient id="bgrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.8} />
                    <stop offset="95%" stopColor="#22d3ee" stopOpacity={0.08} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#142434" strokeDasharray="3 3" />
                <XAxis dataKey="t" tick={{ fill: '#7dd3fc', fontSize: 11 }} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <Tooltip />
                <Area type="monotone" dataKey="malware" stroke="#fb7185" fill="url(#mgrad)" />
                <Area type="monotone" dataKey="benign" stroke="#22d3ee" fill="url(#bgrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </section>
      </aside>
    </div>
  )
}
