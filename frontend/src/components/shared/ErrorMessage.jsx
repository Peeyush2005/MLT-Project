import React from 'react'

export default function ErrorMessage({ message, onRetry }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-8">
      <div className="bg-red-900/30 border border-red-700 rounded-lg p-4 max-w-lg w-full text-center">
        <p className="text-red-400 font-semibold text-lg mb-1">⚠️ Error</p>
        <p className="text-red-300 text-sm">{message}</p>
        {onRetry && (
          <button
            onClick={onRetry}
            className="mt-3 px-4 py-1.5 bg-red-800 hover:bg-red-700 text-red-200 text-sm rounded-md transition-colors"
          >
            Retry
          </button>
        )}
      </div>
    </div>
  )
}
