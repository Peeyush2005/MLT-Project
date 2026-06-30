import React, { useMemo, useState } from 'react'

import { predict } from '../api/client'
import ConfidenceBar from '../components/shared/ConfidenceBar'
import VerdictBadge from '../components/shared/VerdictBadge'

const CATEGORICAL_FIELDS = [
  'ioc_type',
  'threat_type',
  'malware_family',
  'src_country',
  'tags',
  'reporter',
]

const QUICK_PORTS = [53, 80, 443, 4444, 8080, 8443]

function makeDefaultForm(vocab) {
  return {
    ioc_type: vocab.ioc_type?.[0] || '',
    threat_type: vocab.threat_type?.[0] || '',
    malware_family: vocab.malware_family?.[0] || '',
    src_country: vocab.src_country?.[0] || '',
    tags: vocab.tags?.[0] || '',
    reporter: vocab.reporter?.[0] || '',
    confidence_level: 50,
    days_active: 10,
    dst_port: 443,
  }
}

export default function ManualAnalysis({ modelInfo, recentEvents }) {
  const vocab = modelInfo?.categorical_vocabularies || {}
  const [form, setForm] = useState(() => makeDefaultForm(vocab))
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const randomSource = useMemo(() => {
    const candidates = recentEvents
      .map((event) => event.raw_record)
      .filter((record) => record && typeof record === 'object')
    return candidates
  }, [recentEvents])

  function setField(field, value) {
    setForm((s) => ({ ...s, [field]: value }))
  }

  function useRandomSample() {
    setError('')
    setResult(null)
    if (randomSource.length === 0) return
    const picked = randomSource[Math.floor(Math.random() * randomSource.length)]
    setForm({
      ...picked,
      confidence_level: Number(picked.confidence_level),
      days_active: Number(picked.days_active),
      dst_port: Number(picked.dst_port),
    })
  }

  async function submit(e) {
    e.preventDefault()
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const payload = {
        ...form,
        confidence_level: Number(form.confidence_level),
        days_active: Number(form.days_active),
        dst_port: Number(form.dst_port),
      }
      const data = await predict(payload)
      setResult(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
      <section className="border border-cyan-950/80 bg-slate-950/70 rounded-lg p-4">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-sm uppercase tracking-[0.2em] text-cyan-300">Manual Analysis</h2>
          <button
            className="text-xs border border-cyan-700 px-2 py-1 rounded hover:bg-cyan-950/40"
            onClick={useRandomSample}
          >
            Use Random Sample
          </button>
        </div>

        <form className="space-y-4" onSubmit={submit}>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {CATEGORICAL_FIELDS.map((field) => (
              <label key={field} className="text-xs text-slate-300 block">
                <span className="uppercase tracking-wide text-slate-500">{field}</span>
                <select
                  className="mt-1 w-full bg-slate-900 border border-slate-800 rounded px-2 py-2"
                  value={form[field] || ''}
                  onChange={(e) => setField(field, e.target.value)}
                >
                  {(vocab[field] || []).map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </label>
            ))}
          </div>

          <label className="block text-xs text-slate-300">
            <span className="uppercase tracking-wide text-slate-500">confidence_level: {form.confidence_level}</span>
            <input
              type="range"
              min={0}
              max={100}
              value={form.confidence_level}
              onChange={(e) => setField('confidence_level', Number(e.target.value))}
              className="w-full mt-1"
            />
          </label>

          <label className="block text-xs text-slate-300">
            <span className="uppercase tracking-wide text-slate-500">days_active: {form.days_active}</span>
            <input
              type="range"
              min={0}
              max={90}
              value={form.days_active}
              onChange={(e) => setField('days_active', Number(e.target.value))}
              className="w-full mt-1"
            />
          </label>

          <div>
            <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">dst_port</div>
            <input
              type="number"
              min={0}
              max={65535}
              value={form.dst_port}
              onChange={(e) => setField('dst_port', Number(e.target.value))}
              className="w-full bg-slate-900 border border-slate-800 rounded px-2 py-2"
            />
            <div className="flex flex-wrap gap-2 mt-2">
              {QUICK_PORTS.map((port) => (
                <button
                  key={port}
                  type="button"
                  onClick={() => setField('dst_port', port)}
                  className="text-xs px-2 py-1 border border-slate-700 rounded hover:border-cyan-700"
                >
                  {port}
                </button>
              ))}
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full text-sm bg-cyan-700 hover:bg-cyan-600 disabled:opacity-50 py-2 rounded font-semibold"
          >
            {loading ? 'Analyzing...' : 'Analyze IOC'}
          </button>
          {error && <p className="text-xs text-rose-400">{error}</p>}
        </form>
      </section>

      <section className="border border-cyan-950/80 bg-slate-950/70 rounded-lg p-4">
        <h2 className="text-sm uppercase tracking-[0.2em] text-cyan-300 mb-4">Result</h2>
        {!result && !loading && <p className="text-slate-400 text-sm">Submit a record to inspect probabilities.</p>}
        {loading && <p className="text-cyan-200">Running model...</p>}

        {result && (
          <div className="space-y-4">
            <div className="border border-slate-800 rounded p-3 bg-slate-900/70 flex items-center justify-between">
              <VerdictBadge prediction={result.prediction} size="md" />
              <div className="text-right">
                <div className="text-slate-400 text-xs">Confidence</div>
                <div className="text-xl font-mono text-slate-100">{(result.confidence * 100).toFixed(2)}%</div>
              </div>
            </div>

            <ConfidenceBar probabilities={result.all_probabilities} />

            <div className="grid grid-cols-3 gap-2 text-xs">
              <div className="border border-slate-800 rounded p-2">
                <div className="text-slate-500">Class Index</div>
                <div className="font-mono text-slate-200">{result.class_index}</div>
              </div>
              <div className="border border-slate-800 rounded p-2">
                <div className="text-slate-500">Latency</div>
                <div className="font-mono text-slate-200">{result.latency_ms.toFixed(2)} ms</div>
              </div>
              <div className="border border-slate-800 rounded p-2">
                <div className="text-slate-500">Request</div>
                <div className="font-mono text-slate-200">{result.request_id.slice(0, 8)}</div>
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  )
}
