import React, { useEffect, useState } from 'react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
  LabelList,
} from 'recharts'
import { getFeatureImportance } from '../api/client'
import LoadingSpinner from './shared/LoadingSpinner'
import ErrorMessage from './shared/ErrorMessage'

const CYAN_SHADES = [
  '#06b6d4', '#0891b2', '#0e7490', '#155e75',
  '#22d3ee', '#67e8f9', '#a5f3fc', '#cffafe', '#ecfeff',
]

function MetricCard({ label, value, color = 'text-cyan-400' }) {
  return (
    <div className="bg-gray-900 rounded-lg p-4 border border-gray-700 text-center">
      <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">{label}</p>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
    </div>
  )
}

function ConfusionMatrix({ matrix }) {
  if (!matrix || matrix.length < 2) return null
  const [[tn, fp], [fn, tp]] = matrix
  const total = tn + fp + fn + tp
  return (
    <div className="mt-4">
      <p className="text-xs text-gray-400 uppercase tracking-wide mb-3 font-semibold">
        Confusion Matrix (Test Set)
      </p>
      <div className="grid grid-cols-2 gap-1 max-w-xs">
        {/* Header row */}
        <div className="col-span-2 grid grid-cols-2 gap-1 mb-1">
          <div className="text-center text-xs text-gray-500 py-1">Pred: Benign</div>
          <div className="text-center text-xs text-gray-500 py-1">Pred: Malware</div>
        </div>
        {/* TN */}
        <div className="bg-green-900/40 border border-green-700 rounded-lg p-3 text-center">
          <p className="text-xs text-gray-400 mb-1">True Negative</p>
          <p className="text-2xl font-bold text-green-400">{tn}</p>
          <p className="text-xs text-gray-500">{((tn / total) * 100).toFixed(1)}%</p>
        </div>
        {/* FP */}
        <div className="bg-red-900/20 border border-red-800 rounded-lg p-3 text-center">
          <p className="text-xs text-gray-400 mb-1">False Positive</p>
          <p className="text-2xl font-bold text-red-400">{fp}</p>
          <p className="text-xs text-gray-500">{((fp / total) * 100).toFixed(1)}%</p>
        </div>
        {/* FN */}
        <div className="bg-orange-900/20 border border-orange-800 rounded-lg p-3 text-center">
          <p className="text-xs text-gray-400 mb-1">False Negative</p>
          <p className="text-2xl font-bold text-orange-400">{fn}</p>
          <p className="text-xs text-gray-500">{((fn / total) * 100).toFixed(1)}%</p>
        </div>
        {/* TP */}
        <div className="bg-green-900/40 border border-green-700 rounded-lg p-3 text-center">
          <p className="text-xs text-gray-400 mb-1">True Positive</p>
          <p className="text-2xl font-bold text-green-400">{tp}</p>
          <p className="text-xs text-gray-500">{((tp / total) * 100).toFixed(1)}%</p>
        </div>
        {/* Row labels */}
        <div className="col-span-2 grid grid-cols-2 gap-1 mt-1">
          <div className="text-center text-xs text-gray-500 py-1">Actual: Benign</div>
          <div className="text-center text-xs text-gray-500 py-1">Actual: Malware</div>
        </div>
      </div>
    </div>
  )
}

function CustomTooltip({ active, payload }) {
  if (active && payload && payload.length) {
    return (
      <div className="bg-gray-900 border border-cyan-700 rounded-lg px-3 py-2 text-sm shadow-lg">
        <p className="text-cyan-300 font-semibold">{payload[0].payload.feature}</p>
        <p className="text-gray-300">
          Importance:{' '}
          <span className="text-cyan-400 font-bold">
            {payload[0].value.toFixed(4)}
          </span>
        </p>
      </div>
    )
  }
  return null
}

export default function ModelInsights({ modelInfo }) {
  const [importance, setImportance] = useState(null)
  const [impLoading, setImpLoading] = useState(true)
  const [impError, setImpError] = useState(null)

  useEffect(() => {
    setImpLoading(true)
    getFeatureImportance()
      .then((data) => {
        // Normalize: expect { features: [...], importances: [...] } or array of {feature, importance}
        let items = []
        if (Array.isArray(data)) {
          items = data
        } else if (data.features && data.importances) {
          items = data.features.map((f, i) => ({
            feature: f,
            importance: data.importances[i],
          }))
        } else if (Array.isArray(data.feature_importances)) {
          items = data.feature_importances
        } else if (data.feature_importance) {
          items = Object.entries(data.feature_importance).map(([feature, importance]) => ({
            feature,
            importance,
          }))
        }
        // Sort descending
        items.sort((a, b) => b.importance - a.importance)
        setImportance(items)
      })
      .catch((err) => setImpError(err.message))
      .finally(() => setImpLoading(false))
  }, [])

  const metrics = modelInfo?.metrics || {}
  const bestParams = metrics?.best_params || {}

  const chartHeight = importance ? Math.max(300, importance.length * 45) : 300

  return (
    <div className="space-y-8">
      {/* Feature Importance Chart */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <h2 className="text-xl font-bold text-cyan-400 mb-5">
          📈 Feature Importance (XGBoost)
        </h2>
        {impLoading && <LoadingSpinner message="Fetching feature importance..." />}
        {impError && !impLoading && <ErrorMessage message={impError} />}
        {importance && !impLoading && (
          <ResponsiveContainer width="100%" height={chartHeight}>
            <BarChart
              layout="vertical"
              data={importance}
              margin={{ top: 5, right: 80, left: 20, bottom: 5 }}
            >
              <CartesianGrid
                strokeDasharray="3 3"
                horizontal={false}
                stroke="#374151"
              />
              <XAxis
                type="number"
                tick={{ fill: '#9ca3af', fontSize: 11 }}
                tickLine={{ stroke: '#4b5563' }}
                axisLine={{ stroke: '#4b5563' }}
                domain={[0, 'dataMax']}
                tickFormatter={(v) => v.toFixed(3)}
              />
              <YAxis
                type="category"
                dataKey="feature"
                width={110}
                tick={{ fill: '#d1d5db', fontSize: 12, fontFamily: 'monospace' }}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(6,182,212,0.08)' }} />
              <Bar dataKey="importance" radius={[0, 4, 4, 0]} maxBarSize={32}>
                {importance.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={CYAN_SHADES[index % CYAN_SHADES.length]}
                  />
                ))}
                <LabelList
                  dataKey="importance"
                  position="right"
                  formatter={(v) => v.toFixed(4)}
                  style={{ fill: '#9ca3af', fontSize: 11 }}
                />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Model Card */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <h2 className="text-xl font-bold text-cyan-400 mb-5">🗂 Model Card</h2>

        {/* Algorithm info */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 mb-6">
          <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
            <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Algorithm</p>
            <p className="text-cyan-300 font-semibold">XGBoost</p>
            <p className="text-gray-400 text-xs">Binary Classification</p>
          </div>
          <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
            <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Train/Test Split</p>
            <p className="text-cyan-300 font-semibold">80 / 20</p>
            <p className="text-gray-400 text-xs">Stratified</p>
          </div>
          <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
            <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Class Balancing</p>
            <p className="text-cyan-300 font-semibold">SMOTE</p>
            <p className="text-gray-400 text-xs">Synthetic minority oversampling</p>
          </div>
          <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
            <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Hyperparameter Search</p>
            <p className="text-cyan-300 font-semibold">RandomizedSearchCV</p>
            <p className="text-gray-400 text-xs">30 candidates, 5-fold StratifiedKFold</p>
          </div>
          <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
            <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">CV Metric</p>
            <p className="text-cyan-300 font-semibold">ROC-AUC</p>
            <p className="text-gray-400 text-xs">Primary selection criterion</p>
          </div>
          <div className="bg-gray-900 rounded-lg p-3 border border-gray-700">
            <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">Features</p>
            <p className="text-cyan-300 font-semibold">9 total</p>
            <p className="text-gray-400 text-xs">3 numeric, 6 categorical</p>
          </div>
        </div>

        {/* Performance Metrics */}
        <h3 className="text-base font-semibold text-gray-300 mb-3">
          Performance Metrics (Test Set)
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
          <MetricCard
            label="Test Accuracy"
            value={
              metrics.accuracy != null
                ? `${(metrics.accuracy * 100).toFixed(2)}%`
                : '—'
            }
            color="text-green-400"
          />
          <MetricCard
            label="F1 Macro"
            value={metrics.f1_macro != null ? metrics.f1_macro.toFixed(4) : '—'}
            color="text-yellow-400"
          />
          <MetricCard
            label="ROC-AUC"
            value={metrics.roc_auc != null ? metrics.roc_auc.toFixed(4) : '—'}
            color="text-cyan-400"
          />
        </div>

        {/* Confusion Matrix */}
        {metrics.confusion_matrix && (
          <ConfusionMatrix matrix={metrics.confusion_matrix} />
        )}

        {/* Best Params */}
        {Object.keys(bestParams).length > 0 && (
          <div className="mt-6">
            <h3 className="text-base font-semibold text-gray-300 mb-3">
              Best Hyperparameters
            </h3>
            <div className="bg-gray-900 rounded-lg border border-gray-700 p-4 font-mono text-sm overflow-x-auto">
              <pre className="text-green-300">
                {JSON.stringify(bestParams, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
