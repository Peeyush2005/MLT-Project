import React, { useState } from 'react'
import { predict } from '../api/client'
import VerdictBadge from './shared/VerdictBadge'
import ConfidenceBar from './shared/ConfidenceBar'
import LoadingSpinner from './shared/LoadingSpinner'
import ErrorMessage from './shared/ErrorMessage'

const CATEGORICAL_FIELDS = [
  'ioc_type',
  'threat_type',
  'malware_family',
  'src_country',
  'tags',
  'reporter',
]

const QUICK_PORTS = [80, 443, 22, 4444, 8080, 6667]

const RANDOM_SAMPLES = [
  {
    ioc_type: 'ip',
    threat_type: 'c2',
    malware_family: 'mirai',
    src_country: 'RU',
    tags: 'botnet',
    reporter: 'threatfox',
    confidence_level: 85,
    days_active: 42,
    dst_port: 4444,
  },
  {
    ioc_type: 'domain',
    threat_type: 'benign',
    malware_family: 'none',
    src_country: 'US',
    tags: 'whitelist',
    reporter: 'internal',
    confidence_level: 10,
    days_active: 5,
    dst_port: 443,
  },
  {
    ioc_type: 'url',
    threat_type: 'phishing',
    malware_family: 'emotet',
    src_country: 'CN',
    tags: 'phishing',
    reporter: 'abuse_ch',
    confidence_level: 72,
    days_active: 18,
    dst_port: 80,
  },
  {
    ioc_type: 'hash',
    threat_type: 'ransomware',
    malware_family: 'lockbit',
    src_country: 'KP',
    tags: 'apt',
    reporter: 'virustotal',
    confidence_level: 95,
    days_active: 60,
    dst_port: 6667,
  },
]

function buildDefaultForm(modelInfo) {
  const defaults = {}
  CATEGORICAL_FIELDS.forEach((field) => {
    const options = modelInfo?.categorical_vocabularies?.[field] || []
    defaults[field] = options[0] || ''
  })
  defaults.confidence_level = 50
  defaults.days_active = 30
  defaults.dst_port = 443
  return defaults
}

export default function LiveDetection({ modelInfo }) {
  const [form, setForm] = useState(() => buildDefaultForm(modelInfo))
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [sampleIndex, setSampleIndex] = useState(0)

  const vocabs = modelInfo?.categorical_vocabularies || {}

  function handleChange(field, value) {
    setForm((prev) => ({ ...prev, [field]: value }))
  }

  function handleRandomSample() {
    const sample = RANDOM_SAMPLES[sampleIndex % RANDOM_SAMPLES.length]
    // Map sample values to actual vocab options where possible
    const snapped = { ...sample }
    CATEGORICAL_FIELDS.forEach((field) => {
      const opts = vocabs[field] || []
      if (opts.length > 0 && !opts.includes(snapped[field])) {
        snapped[field] = opts[0]
      }
    })
    setForm(snapped)
    setSampleIndex((i) => i + 1)
    setResult(null)
    setError(null)
  }

  async function handleSubmit(e) {
    e.preventDefault()
    setLoading(true)
    setResult(null)
    setError(null)
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
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
      {/* Form Panel */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-xl font-bold text-cyan-400">IOC Record</h2>
          <button
            type="button"
            onClick={handleRandomSample}
            className="flex items-center gap-2 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-200 text-sm rounded-lg border border-gray-600 transition-colors"
          >
            🎲 Use Random Sample
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Categorical fields */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {CATEGORICAL_FIELDS.map((field) => {
              const options = vocabs[field] || []
              return (
                <div key={field}>
                  <label className="block text-xs font-semibold text-gray-400 mb-1 uppercase tracking-wide">
                    {field.replace(/_/g, ' ')}
                  </label>
                  <select
                    value={form[field] || ''}
                    onChange={(e) => handleChange(field, e.target.value)}
                    className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors"
                    required
                  >
                    {options.length === 0 && (
                      <option value="">Loading options...</option>
                    )}
                    {options.map((opt) => (
                      <option key={opt} value={opt}>
                        {opt}
                      </option>
                    ))}
                  </select>
                </div>
              )
            })}
          </div>

          {/* confidence_level slider */}
          <div>
            <label className="block text-xs font-semibold text-gray-400 mb-1 uppercase tracking-wide">
              Confidence Level
              <span className="ml-2 text-cyan-400 font-bold normal-case">
                {form.confidence_level}
              </span>
            </label>
            <div className="flex items-center gap-3">
              <input
                type="range"
                min={0}
                max={100}
                value={form.confidence_level}
                onChange={(e) => handleChange('confidence_level', e.target.value)}
                className="flex-1 accent-cyan-400"
              />
              <input
                type="number"
                min={0}
                max={100}
                value={form.confidence_level}
                onChange={(e) =>
                  handleChange(
                    'confidence_level',
                    Math.min(100, Math.max(0, Number(e.target.value)))
                  )
                }
                className="w-16 bg-gray-900 border border-gray-600 rounded px-2 py-1 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 text-center"
              />
            </div>
          </div>

          {/* days_active slider */}
          <div>
            <label className="block text-xs font-semibold text-gray-400 mb-1 uppercase tracking-wide">
              Days Active
              <span className="ml-2 text-cyan-400 font-bold normal-case">
                {form.days_active}
              </span>
            </label>
            <div className="flex items-center gap-3">
              <input
                type="range"
                min={0}
                max={90}
                value={form.days_active}
                onChange={(e) => handleChange('days_active', e.target.value)}
                className="flex-1 accent-cyan-400"
              />
              <input
                type="number"
                min={0}
                max={90}
                value={form.days_active}
                onChange={(e) =>
                  handleChange(
                    'days_active',
                    Math.min(90, Math.max(0, Number(e.target.value)))
                  )
                }
                className="w-16 bg-gray-900 border border-gray-600 rounded px-2 py-1 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 text-center"
              />
            </div>
          </div>

          {/* dst_port */}
          <div>
            <label className="block text-xs font-semibold text-gray-400 mb-1 uppercase tracking-wide">
              Destination Port
            </label>
            <input
              type="number"
              min={0}
              max={65535}
              value={form.dst_port}
              onChange={(e) => handleChange('dst_port', e.target.value)}
              className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-gray-100 text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 mb-2"
            />
            <div className="flex flex-wrap gap-2">
              {QUICK_PORTS.map((port) => (
                <button
                  key={port}
                  type="button"
                  onClick={() => handleChange('dst_port', port)}
                  className={`px-3 py-1 text-xs rounded-full border transition-colors font-mono ${
                    Number(form.dst_port) === port
                      ? 'bg-cyan-600 border-cyan-400 text-white'
                      : 'bg-gray-700 border-gray-600 text-gray-300 hover:bg-gray-600'
                  }`}
                >
                  {port}
                </button>
              ))}
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 bg-cyan-600 hover:bg-cyan-500 disabled:bg-cyan-900 disabled:cursor-not-allowed text-white font-bold rounded-xl transition-colors text-lg tracking-wide mt-2"
          >
            {loading ? 'Analyzing...' : '🔍 Analyze IOC'}
          </button>
        </form>
      </div>

      {/* Result Panel */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700 flex flex-col">
        <h2 className="text-xl font-bold text-cyan-400 mb-5">Detection Result</h2>

        {!result && !loading && !error && (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center text-gray-500">
              <div className="text-6xl mb-4">🛡️</div>
              <p className="text-lg">Submit an IOC record to see the verdict</p>
              <p className="text-sm mt-2">
                Fill in the form on the left and click "Analyze IOC"
              </p>
            </div>
          </div>
        )}

        {loading && <LoadingSpinner message="Running XGBoost inference..." />}

        {error && !loading && <ErrorMessage message={error} />}

        {result && !loading && (
          <div className="flex-1 flex flex-col gap-5">
            {/* Verdict */}
            <div className="flex flex-col items-center gap-3 py-6 bg-gray-900 rounded-xl border border-gray-700">
              <VerdictBadge prediction={result.prediction} size="lg" />
              <p className="text-3xl font-bold text-gray-100">
                {Math.round((result.confidence ?? 0) * 100)}%
                <span className="text-base text-gray-400 ml-2 font-normal">confidence</span>
              </p>
            </div>

            {/* Probability bar */}
            <div className="bg-gray-900 rounded-xl p-4 border border-gray-700">
              <p className="text-xs text-gray-400 uppercase tracking-wide mb-3 font-semibold">
                Class Probability Distribution
              </p>
              <ConfidenceBar probabilities={result.probabilities} />
            </div>

            {/* Details */}
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                <p className="text-xs text-gray-500 uppercase tracking-wide">Latency</p>
                <p className="text-cyan-400 font-bold text-lg">
                  {result.latency_ms != null ? `${result.latency_ms.toFixed(1)} ms` : '—'}
                </p>
              </div>
              <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
                <p className="text-xs text-gray-500 uppercase tracking-wide">Class Index</p>
                <p className="text-cyan-400 font-bold text-lg">
                  {result.class_index ?? '—'}
                </p>
              </div>
            </div>

            {result.request_id && (
              <p className="text-xs text-gray-600 font-mono text-center">
                Request ID: {result.request_id}
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
