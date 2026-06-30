import React from 'react'

export default function ConfidenceBar({ probabilities, className = '' }) {
  const pBenign = Number(probabilities?.benign ?? probabilities?.[0] ?? 0)
  const pMalware = Number(probabilities?.malware ?? probabilities?.[1] ?? 0)
  const benignPct = Math.max(0, Math.min(100, pBenign * 100))
  const malwarePct = Math.max(0, Math.min(100, pMalware * 100))

  return (
    <div className={`w-full ${className}`}>
      <div className="flex justify-between text-xs text-gray-400 mb-1">
        <span className="text-emerald-300 font-medium">P(Benign) {benignPct.toFixed(1)}%</span>
        <span className="text-rose-300 font-medium">P(Malware) {malwarePct.toFixed(1)}%</span>
      </div>
      <div className="flex h-4 rounded-sm overflow-hidden bg-slate-800/80 border border-cyan-950">
        <div
          className="bg-cyan-400/80 transition-all duration-300 ease-out"
          style={{ width: `${benignPct}%` }}
        >
        </div>
        <div
          className="bg-rose-500/85 transition-all duration-300 ease-out"
          style={{ width: `${malwarePct}%` }}
        />
      </div>
    </div>
  )
}
