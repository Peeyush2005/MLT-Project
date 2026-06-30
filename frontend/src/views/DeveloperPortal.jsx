import React, { useEffect, useMemo, useState } from 'react'
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

import {
  createApiKey,
  getKeyUsage,
  listApiKeys,
  revokeApiKey,
  setActiveApiKey,
} from '../api/client'

export default function DeveloperPortal({ onKeyChanged }) {
  const [label, setLabel] = useState('')
  const [rateLimit, setRateLimit] = useState(60)
  const [keys, setKeys] = useState([])
  const [usage, setUsage] = useState([])
  const [selectedKeyId, setSelectedKeyId] = useState('')
  const [freshKey, setFreshKey] = useState('')
  const [error, setError] = useState('')

  async function loadKeys() {
    try {
      const data = await listApiKeys()
      setKeys(data.keys || [])
      if (!selectedKeyId && data.keys?.length > 0) {
        setSelectedKeyId(data.keys[0].key_id)
      }
    } catch (err) {
      setError(err.message)
    }
  }

  useEffect(() => {
    loadKeys()
  }, [])

  useEffect(() => {
    if (!selectedKeyId) return
    getKeyUsage(selectedKeyId)
      .then((data) => setUsage(data.series || []))
      .catch((err) => setError(err.message))
  }, [selectedKeyId])

  async function submitCreate(e) {
    e.preventDefault()
    setError('')
    setFreshKey('')
    try {
      const created = await createApiKey({
        label: label || 'default',
        rate_limit_per_min: Number(rateLimit),
      })
      setFreshKey(created.api_key)
      setActiveApiKey(created.api_key, `mw_live_sk_....${created.api_key.slice(-4)}`)
      onKeyChanged?.(created.api_key)
      setLabel('')
      await loadKeys()
    } catch (err) {
      setError(err.message)
    }
  }

  async function revoke(id) {
    setError('')
    try {
      await revokeApiKey(id)
      await loadKeys()
    } catch (err) {
      setError(err.message)
    }
  }

  const selected = useMemo(() => keys.find((k) => k.key_id === selectedKeyId), [keys, selectedKeyId])

  return (
    <div className="grid grid-cols-1 xl:grid-cols-[1.2fr_1fr] gap-4">
      <section className="border border-cyan-950/80 bg-slate-950/70 rounded-lg p-4 space-y-4">
        <h2 className="text-sm uppercase tracking-[0.2em] text-cyan-300">Developer Portal</h2>

        <form onSubmit={submitCreate} className="grid grid-cols-1 md:grid-cols-[1fr_auto_auto] gap-2">
          <input
            className="bg-slate-900 border border-slate-800 rounded px-3 py-2 text-sm"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="Key label"
          />
          <input
            className="bg-slate-900 border border-slate-800 rounded px-3 py-2 text-sm w-28"
            type="number"
            min={1}
            max={2000}
            value={rateLimit}
            onChange={(e) => setRateLimit(Number(e.target.value))}
          />
          <button className="bg-cyan-700 hover:bg-cyan-600 rounded px-3 py-2 text-sm font-semibold">
            Generate Key
          </button>
        </form>

        {freshKey && (
          <div className="border border-amber-700/70 bg-amber-900/20 rounded p-3 text-sm">
            <div className="text-amber-300 font-semibold">Save this key now. It will not be shown again.</div>
            <div className="font-mono text-amber-100 mt-1 break-all">{freshKey}</div>
          </div>
        )}

        {error && <p className="text-xs text-rose-400">{error}</p>}

        <div className="overflow-auto border border-slate-800 rounded">
          <table className="w-full text-xs">
            <thead className="bg-slate-900">
              <tr>
                <th className="px-2 py-2 text-left">Masked</th>
                <th className="px-2 py-2 text-left">Label</th>
                <th className="px-2 py-2 text-left">Today</th>
                <th className="px-2 py-2 text-left">Total</th>
                <th className="px-2 py-2 text-left">Rate</th>
                <th className="px-2 py-2 text-left">Status</th>
                <th className="px-2 py-2" />
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => (
                <tr key={key.key_id} className="border-t border-slate-800">
                  <td className="px-2 py-2 font-mono">{key.masked_key}</td>
                  <td className="px-2 py-2">{key.label}</td>
                  <td className="px-2 py-2 font-mono">{key.requests_today}</td>
                  <td className="px-2 py-2 font-mono">{key.requests_total}</td>
                  <td className="px-2 py-2 font-mono">{key.rate_limit_per_min}/m</td>
                  <td className="px-2 py-2">{key.is_active ? 'active' : 'revoked'}</td>
                  <td className="px-2 py-2 text-right space-x-2">
                    <button
                      className="text-cyan-300 hover:text-cyan-100"
                      onClick={() => {
                        setSelectedKeyId(key.key_id)
                      }}
                    >
                      usage
                    </button>
                    {key.is_active && (
                      <button className="text-rose-300 hover:text-rose-100" onClick={() => revoke(key.key_id)}>
                        revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="border border-cyan-950/80 bg-slate-950/70 rounded-lg p-4 space-y-3">
        <h3 className="text-sm uppercase tracking-[0.2em] text-cyan-300">Per-Key Usage (24h)</h3>
        <div className="text-xs text-slate-400">Selected: {selected?.label || 'none'}</div>

        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={usage}>
              <XAxis dataKey="hour" hide />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <Tooltip />
              <Bar dataKey="request_count" fill="#22d3ee" />
              <Bar dataKey="malware_count" fill="#fb7185" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="border border-slate-800 rounded p-3 bg-slate-900/60">
          <div className="text-xs text-slate-400 mb-2">How to use your key</div>
          <pre className="text-[11px] text-emerald-300 overflow-auto font-mono">{`curl -X POST http://localhost:8000/api/predict \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: YOUR_KEY" \\
  -d '{"ioc_type":"domain","threat_type":"botnet_cc","malware_family":"emotet","confidence_level":75,"dst_port":4444,"days_active":15,"src_country":"RU","tags":"c2","reporter":"honeypot_net"}'`}</pre>
        </div>
      </section>
    </div>
  )
}
