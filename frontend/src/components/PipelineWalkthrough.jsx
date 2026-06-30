import React, { useState } from 'react'
import { predict } from '../api/client'
import VerdictBadge from './shared/VerdictBadge'
import LoadingSpinner from './shared/LoadingSpinner'

const PRESET_RECORDS = {
  malicious: {
    label: '🚨 Malicious Example',
    color: 'border-red-600 hover:border-red-400',
    activeColor: 'bg-red-900/30 border-red-500',
    record: {
      ioc_type: 'ip',
      threat_type: 'botnet_cc',
      malware_family: 'emotet',
      src_country: 'RU',
      tags: 'c2',
      reporter: 'honeypot_net',
      confidence_level: 90,
      days_active: 55,
      dst_port: 4444,
    },
  },
  benign: {
    label: '✅ Benign Example',
    color: 'border-green-700 hover:border-green-500',
    activeColor: 'bg-green-900/30 border-green-500',
    record: {
      ioc_type: 'domain',
      threat_type: 'benign',
      malware_family: 'none',
      src_country: 'US',
      tags: 'known_good',
      reporter: 'analyst_team_a',
      confidence_level: 8,
      days_active: 3,
      dst_port: 443,
    },
  },
  ambiguous: {
    label: '⚠️ Ambiguous Example',
    color: 'border-yellow-700 hover:border-yellow-500',
    activeColor: 'bg-yellow-900/20 border-yellow-600',
    record: {
      ioc_type: 'url',
      threat_type: 'phishing',
      malware_family: 'trickbot',
      src_country: 'DE',
      tags: 'suspicious',
      reporter: 'partner_org',
      confidence_level: 48,
      days_active: 22,
      dst_port: 8080,
    },
  },
}

const ANIMATED_STAGES = [4, 6, 8]

function CodeBlock({ children, className = '' }) {
  return (
    <pre
      className={`bg-gray-950 border border-gray-700 rounded-lg p-3 text-xs font-mono text-green-300 overflow-x-auto ${className}`}
    >
      {children}
    </pre>
  )
}

function StageNumber({ n, active, completed }) {
  return (
    <div
      className={`flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center font-bold text-sm border-2 transition-all duration-500 ${
        active
          ? 'bg-cyan-500 border-cyan-300 text-white scale-110 shadow-lg shadow-cyan-500/30'
          : completed
          ? 'bg-cyan-900 border-cyan-600 text-cyan-300'
          : 'bg-gray-800 border-gray-600 text-gray-400'
      }`}
    >
      {completed && !active ? '✓' : n}
    </div>
  )
}

export default function PipelineWalkthrough({ modelInfo }) {
  const [selectedPreset, setSelectedPreset] = useState(null)
  const [activeStages, setActiveStages] = useState([])
  const [runLoading, setRunLoading] = useState(false)
  const [apiResult, setApiResult] = useState(null)
  const [apiError, setApiError] = useState(null)

  const features = modelInfo?.features || []
  const metrics = modelInfo?.metrics || {}
  const vocabs = modelInfo?.categorical_vocabularies || {}
  const iocTypes = vocabs?.ioc_type || []

  async function runPipeline(presetKey) {
    const preset = PRESET_RECORDS[presetKey]
    if (!preset) return

    setSelectedPreset(presetKey)
    setActiveStages([])
    setApiResult(null)
    setApiError(null)
    setRunLoading(false)

    // Animate through stages 4, 6, 8 with delays
    const delays = [0, 600, 1200]
    ANIMATED_STAGES.forEach((stage, i) => {
      setTimeout(() => {
        setActiveStages((prev) => [...prev, stage])
        if (i === ANIMATED_STAGES.length - 1) {
          // Last stage — fire the real API call
          setRunLoading(true)
          predict(preset.record)
            .then((data) => setApiResult(data))
            .catch((err) => setApiError(err.message))
            .finally(() => setRunLoading(false))
        }
      }, delays[i])
    })
  }

  function isStageActive(n) {
    return activeStages.includes(n)
  }

  function isStageCompleted(n) {
    return (
      activeStages.includes(n) &&
      ANIMATED_STAGES.indexOf(n) < ANIMATED_STAGES.indexOf(activeStages[activeStages.length - 1])
    )
  }

  // Build ioc_type mapping display from actual vocab
  const iocTypeMapping = iocTypes
    .map((t, i) => `'${t}' → ${i}`)
    .join(', ')

  const stages = [
    {
      n: 1,
      title: 'Raw IOC Ingestion',
      icon: '📥',
      description:
        'Raw threat-intel records arrive with fields like ioc_type, ioc_value, timestamp, src_country, dst_port, and tags. These represent Indicators of Compromise (IOCs) collected from various sources including threat feeds, honeypots, and security researchers.',
      artifact: features.length > 0 && (
        <div>
          <p className="text-xs text-gray-500 mb-2">Feature columns used by the model:</p>
          <div className="flex flex-wrap gap-2">
            {features.map((f) => (
              <span
                key={f}
                className="px-2 py-1 bg-gray-950 border border-cyan-800 rounded text-cyan-300 text-xs font-mono"
              >
                {f}
              </span>
            ))}
          </div>
        </div>
      ),
    },
    {
      n: 2,
      title: 'Leakage Check & Data Cleaning',
      icon: '🔍',
      description:
        'The original dataset had categorical columns that were near-perfectly correlated with the label (e.g., all benign rows had confidence_level=0, all malicious rows had confidence_level=50). This makes the ML problem trivially solvable and produces misleadingly perfect metrics.',
      description2:
        'To fix this, realistic noise was injected: overlapping distributions, 15-25% mislabeled examples, and mixed category assignments for each feature — creating a genuinely challenging classification task.',
    },
    {
      n: 3,
      title: 'Train/Test Split Before Fitting Encoders',
      icon: '✂️',
      description:
        'The 80/20 stratified split is performed BEFORE fitting any encoder or scaler. This prevents test-set statistics from leaking into training — a common mistake in naive pipelines that fit LabelEncoder on the full dataset first.',
      artifact: (metrics.train_size || metrics.test_size) && (
        <div className="flex gap-4">
          {metrics.train_size != null && (
            <div className="bg-gray-950 border border-gray-700 rounded-lg p-3 text-center">
              <p className="text-xs text-gray-500">Train Size</p>
              <p className="text-xl font-bold text-cyan-400">{metrics.train_size.toLocaleString()}</p>
            </div>
          )}
          {metrics.test_size != null && (
            <div className="bg-gray-950 border border-gray-700 rounded-lg p-3 text-center">
              <p className="text-xs text-gray-500">Test Size</p>
              <p className="text-xl font-bold text-cyan-400">{metrics.test_size.toLocaleString()}</p>
            </div>
          )}
        </div>
      ),
    },
    {
      n: 4,
      title: 'Categorical Encoding',
      icon: '🔢',
      animatable: true,
      description:
        'Each categorical column is label-encoded using sklearn\'s LabelEncoder, fitted on training data only. At inference time, unseen category values fall back to encoder.classes_[0] rather than raising a KeyError — this matches exactly what the production predict_malware() function does.',
      artifact: iocTypes.length > 0 && (
        <div>
          <p className="text-xs text-gray-500 mb-2">
            Example mapping for <span className="text-cyan-400 font-mono">ioc_type</span>:
          </p>
          <CodeBlock>{iocTypeMapping}</CodeBlock>
        </div>
      ),
    },
    {
      n: 5,
      title: 'Class Imbalance Handling (SMOTE)',
      icon: '⚖️',
      description:
        'The dataset has a 9:1 malware-to-benign imbalance (4500 malicious, 500 benign). SMOTE (Synthetic Minority Over-sampling Technique) is applied to the training set ONLY to create synthetic benign samples, producing a balanced training distribution that prevents the model from ignoring the minority class.',
      artifact: metrics.class_balance && (
        <div>
          <p className="text-xs text-gray-500 mb-2">Class balance after SMOTE:</p>
          <CodeBlock>{JSON.stringify(metrics.class_balance, null, 2)}</CodeBlock>
        </div>
      ),
    },
    {
      n: 6,
      title: 'Model Training (XGBoost + Hyperparameter Search)',
      icon: '🧠',
      animatable: true,
      description:
        'An XGBoost binary classifier is tuned using RandomizedSearchCV with 30 random parameter combinations evaluated via 5-fold StratifiedKFold cross-validation. The objective is binary:logistic and the best combination is selected by mean ROC-AUC score across folds.',
      artifact: metrics.best_params && Object.keys(metrics.best_params).length > 0 && (
        <div>
          <p className="text-xs text-gray-500 mb-2">Best hyperparameters found:</p>
          <CodeBlock>{JSON.stringify(metrics.best_params, null, 2)}</CodeBlock>
        </div>
      ),
    },
    {
      n: 7,
      title: 'Evaluation',
      icon: '📊',
      description:
        'The tuned model is evaluated on the 20% hold-out test set that was never seen during training or hyperparameter search. This gives an unbiased estimate of real-world generalization performance.',
      artifact: (metrics.accuracy != null || metrics.confusion_matrix) && (
        <div className="space-y-3">
          <div className="flex flex-wrap gap-3">
            {metrics.accuracy != null && (
              <div className="bg-gray-950 border border-gray-700 rounded-lg p-3 text-center min-w-[90px]">
                <p className="text-xs text-gray-500">Accuracy</p>
                <p className="text-lg font-bold text-green-400">
                  {(metrics.accuracy * 100).toFixed(2)}%
                </p>
              </div>
            )}
            {metrics.f1_macro != null && (
              <div className="bg-gray-950 border border-gray-700 rounded-lg p-3 text-center min-w-[90px]">
                <p className="text-xs text-gray-500">F1 Macro</p>
                <p className="text-lg font-bold text-yellow-400">
                  {metrics.f1_macro.toFixed(4)}
                </p>
              </div>
            )}
            {metrics.roc_auc != null && (
              <div className="bg-gray-950 border border-gray-700 rounded-lg p-3 text-center min-w-[90px]">
                <p className="text-xs text-gray-500">ROC-AUC</p>
                <p className="text-lg font-bold text-cyan-400">
                  {metrics.roc_auc.toFixed(4)}
                </p>
              </div>
            )}
          </div>
          {metrics.confusion_matrix && metrics.confusion_matrix.length >= 2 && (
            <div>
              <p className="text-xs text-gray-500 mb-1">Confusion Matrix:</p>
              <CodeBlock>
                {`          Pred Benign  Pred Malware\nActual Benign  ${metrics.confusion_matrix[0][0]}         ${metrics.confusion_matrix[0][1]}\nActual Malware ${metrics.confusion_matrix[1][0]}         ${metrics.confusion_matrix[1][1]}`}
              </CodeBlock>
            </div>
          )}
        </div>
      ),
    },
    {
      n: 8,
      title: 'Inference (predict_malware() Contract)',
      icon: '⚡',
      animatable: true,
      description:
        'At inference time, the predict_malware() function accepts a raw dict with human-readable values, reindexes columns to the training order, label-encodes categoricals (with unseen-category fallback to encoder.classes_[0]), runs XGBoost predict_proba(), and returns the predicted label, class index, confidence, and per-class probabilities.',
      artifact: (
        <div>
          <CodeBlock>{`def predict_malware(record: dict) -> dict:
    df = pd.DataFrame([record])[FEATURE_COLS]
    for col in CATEGORICAL_COLS:
        le = label_encoders[col]
        df[col] = df[col].map(
            lambda x: x if x in le.classes_ else le.classes_[0]
        )
        df[col] = le.transform(df[col])
    proba = model.predict_proba(df)[0]
    label = "malware" if proba[1] > 0.5 else "benign"
    return {"prediction": label, "confidence": max(proba),
            "all_probabilities": {"benign": proba[0], "malware": proba[1]}}`}</CodeBlock>
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-8">
      {/* Preset controls */}
      <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
        <h2 className="text-base font-bold text-cyan-400 mb-3">
          🧪 Run a Sample Through the Pipeline
        </h2>
        <p className="text-sm text-gray-400 mb-4">
          Select an IOC preset to see it animate through encoding → training → inference stages
          with a real API call at Stage 8.
        </p>
        <div className="flex flex-wrap gap-3">
          {Object.entries(PRESET_RECORDS).map(([key, preset]) => (
            <button
              key={key}
              onClick={() => runPipeline(key)}
              disabled={runLoading}
              className={`px-4 py-2 rounded-lg border text-sm font-semibold transition-all duration-200 ${
                selectedPreset === key
                  ? preset.activeColor + ' text-white'
                  : preset.color + ' bg-gray-900 text-gray-300'
              } disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              {preset.label}
            </button>
          ))}
        </div>

        {selectedPreset && (
          <div className="mt-4 bg-gray-900 rounded-lg p-3 border border-gray-700">
            <p className="text-xs text-gray-500 mb-2 uppercase tracking-wide">Record being analyzed:</p>
            <CodeBlock>{JSON.stringify(PRESET_RECORDS[selectedPreset].record, null, 2)}</CodeBlock>
          </div>
        )}
      </div>

      {/* Pipeline stages */}
      <div className="space-y-4">
        {stages.map((stage, idx) => {
          const active = isStageActive(stage.n)
          const completed = isStageCompleted(stage.n)
          const isAnimatable = stage.animatable

          return (
            <div
              key={stage.n}
              className={`relative flex gap-4 rounded-xl border p-5 transition-all duration-500 ${
                active && isAnimatable
                  ? 'border-cyan-500 bg-cyan-900/10 shadow-lg shadow-cyan-900/20'
                  : 'border-gray-700 bg-gray-800'
              }`}
            >
              {/* Connector line */}
              {idx < stages.length - 1 && (
                <div className="absolute left-9 top-[4.5rem] w-0.5 h-6 bg-gray-700 z-0" />
              )}

              <StageNumber
                n={stage.n}
                active={active && isAnimatable}
                completed={completed && isAnimatable}
              />

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-xl">{stage.icon}</span>
                  <h3
                    className={`text-base font-bold transition-colors duration-500 ${
                      active && isAnimatable ? 'text-cyan-300' : 'text-gray-200'
                    }`}
                  >
                    Stage {stage.n}: {stage.title}
                  </h3>
                  {active && isAnimatable && (
                    <span className="ml-2 text-xs px-2 py-0.5 bg-cyan-500/20 border border-cyan-500 rounded-full text-cyan-400 animate-pulse">
                      ACTIVE
                    </span>
                  )}
                </div>
                <p className="text-sm text-gray-400 leading-relaxed">{stage.description}</p>
                {stage.description2 && (
                  <p className="text-sm text-gray-400 leading-relaxed mt-2">
                    {stage.description2}
                  </p>
                )}
                {stage.artifact && (
                  <div className="mt-3">{stage.artifact}</div>
                )}

                {/* Stage 8 live result */}
                {stage.n === 8 && (runLoading || apiResult || apiError) && (
                  <div className="mt-4 bg-gray-950 rounded-xl border border-cyan-800 p-4">
                    <p className="text-xs text-cyan-400 font-semibold uppercase tracking-wide mb-3">
                      Live API Response
                    </p>
                    {runLoading && <LoadingSpinner message="Calling /api/predict..." />}
                    {apiError && !runLoading && (
                      <p className="text-red-400 text-sm">{apiError}</p>
                    )}
                    {apiResult && !runLoading && (
                      <div className="space-y-3">
                        <div className="flex items-center gap-4 flex-wrap">
                          <VerdictBadge prediction={apiResult.prediction} size="md" />
                          <span className="text-2xl font-bold text-gray-100">
                            {Math.round((apiResult.confidence ?? 0) * 100)}%
                            <span className="text-sm text-gray-400 ml-1 font-normal">confidence</span>
                          </span>
                        </div>
                        {apiResult.all_probabilities && (
                          <div className="flex gap-3 text-sm">
                            <span className="text-green-400">
                              P(Benign):{' '}
                              <strong>
                                {(
                                  (apiResult.all_probabilities.benign ??
                                    apiResult.all_probabilities[0] ??
                                    0) * 100
                                ).toFixed(1)}
                                %
                              </strong>
                            </span>
                            <span className="text-gray-500">|</span>
                            <span className="text-red-400">
                              P(Malware):{' '}
                              <strong>
                                {(
                                  (apiResult.all_probabilities.malware ??
                                    apiResult.all_probabilities[1] ??
                                    0) * 100
                                ).toFixed(1)}
                                %
                              </strong>
                            </span>
                          </div>
                        )}
                        <CodeBlock>{JSON.stringify(apiResult, null, 2)}</CodeBlock>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
