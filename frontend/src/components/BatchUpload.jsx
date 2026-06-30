import React, { useMemo, useRef, useState } from 'react'

import { predictCSV } from '../api/client'
import VerdictBadge from './shared/VerdictBadge'

function parseCSVPreview(text, maxRows = 10) {
  const lines = text.split(/\r?\n/).filter((line) => line.trim())
  if (lines.length === 0) return { headers: [], rows: [] }

  const headers = lines[0].split(',').map((header) => header.trim())
  const rows = lines.slice(1, 1 + maxRows).map((line) => {
    const cols = line.split(',').map((value) => value.trim())
    const row = {}
    headers.forEach((header, idx) => {
      row[header] = cols[idx] || ''
    })
    return row
  })
  return { headers, rows }
}

function downloadCSV(base64Content) {
  const bytes = Uint8Array.from(atob(base64Content), (char) => char.charCodeAt(0))
  const blob = new Blob([bytes], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = 'annotated_results.csv'
  anchor.click()
  URL.revokeObjectURL(url)
}

export default function BatchUpload() {
  const [file, setFile] = useState(null)
  const [preview, setPreview] = useState({ headers: [], rows: [] })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [response, setResponse] = useState(null)
  const fileRef = useRef(null)

  function handleFile(fileObj) {
    if (!fileObj || !fileObj.name.endsWith('.csv')) {
      setError('Please select a .csv file')
      return
    }

    setFile(fileObj)
    setResponse(null)
    setError('')

    const reader = new FileReader()
    reader.onload = (event) => {
      setPreview(parseCSVPreview(String(event.target?.result || '')))
    }
    reader.readAsText(fileObj)
  }

  async function submit() {
    if (!file) return
    setLoading(true)
    setError('')
    try {
      const data = await predictCSV(file)
      setResponse(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const tableRows = useMemo(() => response?.results || [], [response])
  const errorRows = useMemo(() => response?.errors || [], [response])
  const summary = response?.summary || {}

  return (
    <div className="space-y-4">
      <div
        className="border border-dashed border-cyan-800 rounded p-6 text-center bg-slate-900/60 cursor-pointer"
        onClick={() => fileRef.current?.click()}
        onDrop={(e) => {
          e.preventDefault()
          handleFile(e.dataTransfer.files?.[0])
        }}
        onDragOver={(e) => e.preventDefault()}
      >
        <input
          ref={fileRef}
          type="file"
          accept=".csv"
          className="hidden"
          onChange={(e) => handleFile(e.target.files?.[0])}
        />
        <p className="text-slate-200">Drop CSV file or click to select</p>
        {file && <p className="text-cyan-300 text-sm mt-1">{file.name}</p>}
      </div>

      {preview.headers.length > 0 && (
        <div className="border border-slate-800 rounded p-3 bg-slate-900/50">
          <div className="text-xs text-slate-400 mb-2">Preview</div>
          <div className="overflow-auto">
            <table className="w-full text-xs">
              <thead>
                <tr>
                  {preview.headers.map((header) => (
                    <th key={header} className="text-left px-2 py-1 text-slate-400">
                      {header}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {preview.rows.map((row, idx) => (
                  <tr key={idx} className="border-t border-slate-800">
                    {preview.headers.map((header) => (
                      <td key={header} className="px-2 py-1 font-mono text-slate-200">
                        {row[header]}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <button
            className="mt-3 bg-cyan-700 hover:bg-cyan-600 px-3 py-2 rounded text-sm"
            disabled={loading}
            onClick={submit}
          >
            {loading ? 'Analyzing...' : 'Submit CSV'}
          </button>
        </div>
      )}

      {error && <div className="text-rose-400 text-sm">{error}</div>}

      {response && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
            <div className="border border-slate-800 rounded p-2">total_rows: {summary.total_rows}</div>
            <div className="border border-slate-800 rounded p-2">processed: {summary.processed}</div>
            <div className="border border-slate-800 rounded p-2">malware: {summary.malware_count}</div>
            <div className="border border-slate-800 rounded p-2">errors: {summary.error_count}</div>
          </div>

          <button
            className="bg-emerald-700 hover:bg-emerald-600 px-3 py-2 rounded text-sm"
            onClick={() => downloadCSV(response.csv_content)}
          >
            Download Annotated CSV
          </button>

          <div className="overflow-auto border border-slate-800 rounded">
            <table className="w-full text-xs">
              <thead className="bg-slate-900">
                <tr>
                  <th className="px-2 py-2 text-left">Row</th>
                  <th className="px-2 py-2 text-left">Verdict</th>
                  <th className="px-2 py-2 text-left">Confidence</th>
                  <th className="px-2 py-2 text-left">Port</th>
                </tr>
              </thead>
              <tbody>
                {tableRows.map((row) => (
                  <tr key={row.row_index} className="border-t border-slate-800">
                    <td className="px-2 py-2 font-mono">{row.row_index}</td>
                    <td className="px-2 py-2">
                      <VerdictBadge prediction={row.prediction} size="sm" />
                    </td>
                    <td className="px-2 py-2 font-mono">{(row.confidence * 100).toFixed(2)}%</td>
                    <td className="px-2 py-2 font-mono">{row.input.dst_port}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {errorRows.length > 0 && (
            <div className="border border-rose-800 rounded p-3 bg-rose-950/20">
              <p className="text-xs text-rose-300">Row errors</p>
              {errorRows.map((row) => (
                <div key={row.row_index} className="text-xs text-rose-200 font-mono">
                  row {row.row_index}: {row.error}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
