import React from 'react'
import BatchUploadPanel from '../components/BatchUpload'

export default function BatchUpload({ modelInfo }) {
  return (
    <div className="border border-cyan-950/80 bg-slate-950/70 rounded-lg p-4">
      <h2 className="text-sm uppercase tracking-[0.2em] text-cyan-300 mb-4">Batch / CSV Upload</h2>
      <BatchUploadPanel modelInfo={modelInfo} />
    </div>
  )
}
