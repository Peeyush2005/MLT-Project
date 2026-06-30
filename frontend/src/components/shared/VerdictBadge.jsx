import React from 'react'

export default function VerdictBadge({ prediction, size = 'md' }) {
  const isMalware = prediction === 'malware' || prediction === 1

  const sizeClasses = {
    sm: 'text-sm px-3 py-1',
    md: 'text-lg px-5 py-2',
    lg: 'text-2xl px-8 py-4',
  }

  return (
    <span
      className={`inline-flex items-center gap-2 font-bold rounded-lg border ${sizeClasses[size]} ${
        isMalware
          ? 'bg-red-900/40 border-red-500 text-red-400'
          : 'bg-green-900/40 border-green-500 text-green-400'
      }`}
    >
      {isMalware ? '🚨 MALWARE' : '✅ BENIGN'}
    </span>
  )
}
