import React from 'react'

function StatCard({ label, value, accent }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4 backdrop-blur">
      <div className="text-[11px] uppercase tracking-[0.24em] text-slate-500">{label}</div>
      <div className={`mt-2 text-2xl font-semibold ${accent}`}>{value}</div>
    </div>
  )
}

function FeatureCard({ title, body }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-950/60 p-5 transition hover:border-cyan-700/60 hover:bg-slate-950/80">
      <div className="text-sm font-semibold text-slate-100">{title}</div>
      <p className="mt-2 text-sm leading-6 text-slate-400">{body}</p>
    </div>
  )
}

export default function LandingPage({ onEnterDashboard }) {
  return (
    <div className="min-h-screen bg-app text-slate-100">
      <div className="mx-auto max-w-7xl px-6 py-8">
        <header className="flex flex-wrap items-center justify-between gap-4 rounded-3xl border border-cyan-950/70 bg-[#07111a]/80 px-6 py-4 backdrop-blur">
          <div className="flex items-center gap-4">
            <div className="grid h-12 w-12 place-items-center rounded-2xl border border-cyan-700 text-[11px] font-bold tracking-[0.3em] text-cyan-300">
              SIO
            </div>
            <div>
              <div className="text-xs uppercase tracking-[0.38em] text-cyan-300">SentinelIOC</div>
              <div className="mt-1 text-sm text-slate-400">A realtime malware and IOC operations console powered by an existing XGBoost classifier</div>
            </div>
          </div>

          <button
            onClick={onEnterDashboard}
            className="rounded-xl border border-cyan-500 bg-cyan-500/10 px-4 py-2 text-sm font-semibold text-cyan-200 transition hover:bg-cyan-500/20"
          >
            Open Dashboard
          </button>
        </header>

        <section className="grid gap-10 py-16 lg:grid-cols-[1.2fr_0.8fr] lg:items-center">
          <div>
            <div className="inline-flex rounded-full border border-rose-800/60 bg-rose-950/30 px-3 py-1 text-[11px] uppercase tracking-[0.24em] text-rose-300">
              Ambient stream + scenario injection + API product controls
            </div>
            <h1 className="mt-6 max-w-4xl text-5xl font-semibold leading-tight text-slate-50 md:text-6xl">
              SentinelIOC turns a static malware classifier into a live SOC experience.
            </h1>
            <p className="mt-6 max-w-2xl text-lg leading-8 text-slate-400">
              This platform wraps a trained XGBoost IOC classifier in a fullstack control plane with live traffic simulation,
              attack scenario injection, key-based access, rate limiting, audit logs, batch analysis, and model explainability.
            </p>

            <div className="mt-8 flex flex-wrap gap-3">
              <button
                onClick={onEnterDashboard}
                className="rounded-xl bg-cyan-500 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
              >
                Launch Main Dashboard
              </button>
              <a
                href="#overview"
                className="rounded-xl border border-slate-700 px-5 py-3 text-sm font-semibold text-slate-200 transition hover:border-slate-500"
              >
                Explore Features
              </a>
            </div>
          </div>

          <div className="grid gap-4">
            <div className="rounded-3xl border border-cyan-950/70 bg-slate-950/70 p-5 shadow-[0_0_80px_rgba(34,211,238,0.08)]">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <div className="text-[11px] uppercase tracking-[0.28em] text-cyan-300">System Snapshot</div>
                  <div className="mt-1 text-sm text-slate-400">What users step into after the landing page</div>
                </div>
                <div className="rounded-full border border-emerald-700 px-2 py-1 text-[11px] uppercase tracking-[0.2em] text-emerald-300">
                  Live
                </div>
              </div>

              <div className="mt-4 grid gap-4 sm:grid-cols-2">
                <StatCard label="Traffic Layer" value="Realtime Stream" accent="text-cyan-300" />
                <StatCard label="Simulation" value="Attack Scenarios" accent="text-rose-300" />
                <StatCard label="Access Model" value="API Keys + Limits" accent="text-amber-300" />
                <StatCard label="Insights" value="Model + Pipeline" accent="text-emerald-300" />
              </div>
            </div>
          </div>
        </section>

        <section id="overview" className="py-4">
          <div className="mb-6 text-xs uppercase tracking-[0.32em] text-slate-500">Core Experience</div>
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <FeatureCard
              title="Live Feed"
              body="Analyst-facing event feed with ambient IOC traffic, injected scenario events, confidence bars, and a rolling malware-versus-benign chart."
            />
            <FeatureCard
              title="Manual + Batch Analysis"
              body="Single-record triage, drag-and-drop CSV processing, per-row validation, and annotated export backed by the real prediction API."
            />
            <FeatureCard
              title="Developer Portal"
              body="Real API key generation, one-time key reveal, masked-key management, per-key rate limits, and hourly usage telemetry."
            />
            <FeatureCard
              title="Explainability Layer"
              body="Feature importance, training metrics, and a pipeline walkthrough that maps raw IOC ingestion to final malware verdicts."
            />
          </div>
        </section>
      </div>
    </div>
  )
}
