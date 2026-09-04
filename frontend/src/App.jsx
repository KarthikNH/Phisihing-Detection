import React, { useState, useEffect } from 'react';
import {
  ShieldAlert, ShieldCheck, Zap, BarChart3, MessageSquare, AlertTriangle,
  Cpu, Activity, Info, RefreshCw, Send, Lock, ArrowRight, CheckCircle2,
  ExternalLink, Terminal, Eye, Shield, Globe, Radio, Sparkles, X
} from 'lucide-react';

// ============================================================
// PHISHGUARD API CONFIGURATION
// ============================================================

// GitHub Pages build receives:
// VITE_API_URL=https://phisihing-detection-rs1l.onrender.com
//
// Local development falls back to:
// http://127.0.0.1:8000
const API_URL = (
  import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'
).replace(/\/$/, '');

// Verification sample URLs
const SAMPLE_URLS = [
  {
    label: 'Google (Verified Safe)',
    url: 'https://www.google.com'
  },
  {
    label: 'Linux GitHub (Verified Safe)',
    url: 'https://github.com/torvalds/linux'
  },
  {
    label: 'PayPal Spoof (Phishing)',
    url: 'http://paypal-security-update.xyz/login?id=99283'
  },
  {
    label: 'IP Host Admin (Suspicious)',
    url: 'http://192.168.1.1/admin/login'
  }
];

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [error, setError] = useState(null);
  const [backendHealth, setBackendHealth] = useState(null);
  const [metricsData, setMetricsData] = useState(null);

  // Chatbot drawer state
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState([
    {
      sender: 'ai',
      text:
        'Greetings. I am PHISHGUARD AI, your real-time threat intelligence analyst. Enter a URL above to inspect machine learning telemetry, or select a prompt below.'
    }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);

  // ============================================================
  // API HELPER
  // ============================================================
  //
  // IMPORTANT:
  // GitHub Pages cannot use the Vite development proxy.
  // Therefore production requests must go directly to Render.
  //
  // Example:
  // https://phisihing-detection-rs1l.onrender.com/api/analyze
  //
  // Local:
  // http://127.0.0.1:8000/api/analyze
  // ============================================================

  const fetchWithFallback = async (endpoint, options = {}) => {
    const path = endpoint.startsWith('/')
      ? endpoint
      : `/ ${endpoint} `;

    const url = `${API_URL}${path} `;

    console.log(`[PHISHGUARD API] ${options.method || 'GET'} ${url} `);

    return fetch(url, options);
  };

  // ============================================================
  // HEALTH CHECK
  // ============================================================

  useEffect(() => {
    checkHealth();
    loadMetrics();
  }, []);

  const checkHealth = async () => {
    try {
      const res = await fetchWithFallback('/api/health');

      if (res.ok) {
        const data = await res.json();
        console.log('[PHISHGUARD] Backend healthy:', data);
        setBackendHealth(data);
      } else {
        console.error(
          '[PHISHGUARD] Health check failed:',
          res.status
        );
        setBackendHealth({ status: 'offline' });
      }
    } catch (err) {
      console.error('[PHISHGUARD] Health connection error:', err);
      setBackendHealth({ status: 'offline' });
    }
  };

  // ============================================================
  // LOAD MODEL METRICS
  // ============================================================

  const loadMetrics = async () => {
    try {
      const res = await fetchWithFallback('/api/metrics');

      if (res.ok) {
        const data = await res.json();
        console.log('[PHISHGUARD] Metrics loaded:', data);
        setMetricsData(data);
      } else {
        console.warn(
          '[PHISHGUARD] Metrics request failed:',
          res.status
        );
      }
    } catch (e) {
      console.warn(
        '[PHISHGUARD] Backend metrics not yet loaded:',
        e
      );
    }
  };

  // ============================================================
  // URL ANALYSIS
  // ============================================================

  const handleAnalyze = async (targetUrl = urlInput) => {
    const rawUrl =
      targetUrl !== undefined && targetUrl !== null
        ? targetUrl
        : urlInput;

    const trimmed =
      typeof rawUrl === 'string'
        ? rawUrl.trim()
        : '';

    if (!trimmed) {
      setError(
        'ANALYSIS UNAVAILABLE: Please enter a target URL before scanning.'
      );
      return;
    }

    setLoading(true);
    setError(null);
    setAnalysisResult(null);

    try {
      // IMPORTANT:
      // This MUST be POST /api/analyze.
      const res = await fetchWithFallback('/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: trimmed
        })
      });

      if (!res.ok) {
        let errDetail =
          'Security engine could not be reached. Check the API deployment and try again.';

        try {
          const errData = await res.json();

          if (errData && errData.detail) {
            errDetail = errData.detail;
          }
        } catch {
          if (res.status === 405) {
            errDetail =
              'ANALYSIS UNAVAILABLE: The analysis endpoint requires POST with JSON payload.';
          } else if (res.status === 404) {
            errDetail =
              'ANALYSIS UNAVAILABLE: API analysis endpoint was not found.';
          }
        }

        throw new Error(errDetail);
      }

      const data = await res.json();

      console.log('[PHISHGUARD] Analysis result:', data);

      setAnalysisResult(data);

      // Push scan context update into chatbot
      setChatMessages(prev => [
        ...prev,
        {
          sender: 'ai',
          text:
            `Telemetry synchronized for \`${data.url}\`.\n\n` +
            `• Risk Level: **${data.risk_level}**\n` +
            `• Composite Index: **${data.risk_score}/100**\n` +
            `• Phishing Probability: **${(data.phishing_probability * 100).toFixed(1)}%**\n` +
            `• Anomaly Index: **${Number(data.anomaly_score).toFixed(2)}**\n\n` +
            `Ask me why this was flagged or what actions you should take.`
        }
      ]);
    } catch (err) {
      console.error('[PHISHGUARD] Analysis error:', err);

      setError(
        err.message ||
        'ANALYSIS UNAVAILABLE: Security engine could not be reached.'
      );
    } finally {
      setLoading(false);
    }
  };

  // ============================================================
  // CHAT
  // ============================================================

  const handleSendChat = async (queryText = chatInput) => {
    const text = queryText || chatInput;

    if (!text || !text.trim()) {
      return;
    }

    const newMessages = [
      ...chatMessages,
      {
        sender: 'user',
        text
      }
    ];

    setChatMessages(newMessages);
    setChatInput('');
    setChatLoading(true);

    try {
      const res = await fetchWithFallback('/api/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          query: text,
          context: analysisResult
        })
      });

      if (res.ok) {
        const data = await res.json();

        setChatMessages(prev => [
          ...prev,
          {
            sender: 'ai',
            text: data.response,
            engine: data.engine
          }
        ]);
      } else {
        let message =
          'ASSISTANT UNAVAILABLE: Unable to process chat request at this time.';

        try {
          const errorData = await res.json();

          if (errorData?.detail) {
            message = errorData.detail;
          }
        } catch {
          // Keep default message
        }

        setChatMessages(prev => [
          ...prev,
          {
            sender: 'ai',
            text: message
          }
        ]);
      }
    } catch (err) {
      console.error('[PHISHGUARD] Chat error:', err);

      setChatMessages(prev => [
        ...prev,
        {
          sender: 'ai',
          text:
            'ASSISTANT UNAVAILABLE: Could not reach PHISHGUARD AI service.'
        }
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  // ============================================================
  // RISK BADGE
  // ============================================================

  const getRiskBadgeClass = (level) => {
    switch (level) {
      case 'CRITICAL':
        return 'badge-critical';

      case 'HIGH':
        return 'badge-high';

      case 'MEDIUM':
        return 'badge-medium';

      case 'LOW':
        return 'badge-low';

      default:
        return 'badge-low';
    }
  };

  // ============================================================
  // SECURITY RECOMMENDATION
  // ============================================================

  const getRecommendation = (level) => {
    switch (level) {
      case 'CRITICAL':
      case 'HIGH':
        return {
          title:
            'IMMEDIATE THREAT DETECTED — DO NOT VISIT LINK',
          desc:
            'High probability of phishing or credential harvesting. Do not submit passwords, payment credentials, or personal information. Close the tab immediately.',
          type: 'danger'
        };

      case 'MEDIUM':
        return {
          title:
            'EVALUATE WITH CAUTION — SUSPICIOUS PATTERNS',
          desc:
            'Unusual lexical features, non-standard subdomains, or high entropy detected. Verify sender and domain spelling before continuing.',
          type: 'warning'
        };

      default:
        return {
          title:
            'VERIFIED LOW RISK — SAFE TO PROCEED',
          desc:
            'Domain structure matches normal web conventions with negligible anomaly signals. Maintain standard web hygiene and HTTPS lock verification.',
          type: 'safe'
        };
    }
  };

  return (
    <div className="min-h-screen flex flex-col relative text-slate-100 bg-[#040508] selection:bg-cyan-500/30 selection:text-white">

      {/* ======================================================
          TOP STATUS BAR
      ====================================================== */}

      <div className="border-b border-white/[0.06] bg-[#050609]/90 backdrop-blur-md px-6 py-2.5 text-[11px] font-mono tracking-wider flex justify-between items-center text-slate-400">

        <div className="flex items-center gap-4">

          <span className="flex items-center gap-1.5 text-slate-300 font-medium">

            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse shadow-sm shadow-cyan-400" />

            PHISHGUARD THREAT DEFENSE PLATFORM

          </span>

          <span className="hidden sm:inline text-white/[0.15]">
            |
          </span>

          <span className="hidden sm:inline text-slate-500">
            ML INFERENCE ENGINE v1.0
          </span>

        </div>

        <div className="flex items-center gap-4">

          <div className="flex items-center gap-2">

            <span
              className={`w-2 h-2 rounded-full ${backendHealth?.status === 'healthy'
                ? 'bg-emerald-400 shadow-sm shadow-emerald-400 animate-ping'
                : 'bg-rose-500'
                }`}
            />

            <span
              className={
                backendHealth?.status === 'healthy'
                  ? 'text-emerald-400 font-bold'
                  : 'text-rose-400 font-bold'
              }
            >
              {backendHealth?.status === 'healthy'
                ? 'API RUNNING // MODEL ACTIVE'
                : 'API OFFLINE'}
            </span>

          </div>

        </div>

      </div>

      {/* ======================================================
          HEADER
      ====================================================== */}

      <header className="border-b border-white/[0.06] bg-[#050609]/80 backdrop-blur-xl sticky top-0 z-40 px-6 py-4">

        <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">

          <div className="flex items-center gap-3">

            <div className="w-9 h-9 rounded-lg bg-white/[0.04] border border-white/[0.1] flex items-center justify-center text-cyan-400 shadow-inner">

              <Shield className="w-5 h-5 text-cyan-400" />

            </div>

            <div>

              <div className="flex items-center gap-2">

                <span className="editorial-title text-2xl tracking-tight text-white font-black">

                  PHISH
                  <span className="text-cyan-400">
                    GUARD
                  </span>

                </span>

                <span className="text-[9px] px-2 py-0.5 rounded bg-white/[0.06] text-slate-300 font-mono border border-white/[0.08] tracking-widest">
                  SEC-OPS
                </span>

              </div>

            </div>

          </div>

          <nav className="flex items-center gap-1.5 bg-black/40 border border-white/[0.08] p-1 rounded-xl">

            <button
              onClick={() => setActiveTab('scanner')}
              className={`px-4 py-1.5 rounded-lg text-xs font-mono font-medium transition-all flex items-center gap-2 ${activeTab === 'scanner'
                ? 'bg-white/[0.1] text-white border border-white/[0.12] shadow-sm'
                : 'text-slate-400 hover:text-white'
                }`}
            >
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              THREAT SCANNER
            </button>

            <button
              onClick={() => setActiveTab('intelligence')}
              className={`px-4 py-1.5 rounded-lg text-xs font-mono font-medium transition-all flex items-center gap-2 ${activeTab === 'intelligence'
                ? 'bg-white/[0.1] text-white border border-white/[0.12] shadow-sm'
                : 'text-slate-400 hover:text-white'
                }`}
            >
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              MODEL INTELLIGENCE
            </button>

          </nav>

          <div className="flex items-center gap-3">

            <button
              onClick={() => setChatOpen(!chatOpen)}
              className="px-3.5 py-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 hover:bg-cyan-500/20 transition-all flex items-center gap-2 text-xs font-mono font-bold"
            >
              <MessageSquare className="w-4 h-4 text-cyan-400" />
              <span>PHISHGUARD AI</span>
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            </button>

          </div>

        </div>

      </header>

      {/* ======================================================
          MAIN
      ====================================================== */}

      <main className="max-w-7xl mx-auto px-6 pt-12 pb-24 w-full flex-grow relative">

        {/* ====================================================
            SCANNER TAB
        ==================================================== */}

        {activeTab === 'scanner' && (

          <div className="space-y-16">

            <div className="relative text-center max-w-4xl mx-auto pt-6 pb-4">

              {/* Radar */}

              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[540px] h-[540px] pointer-events-none -z-10 select-none overflow-hidden">

                <div className="radar-ring w-[140px] h-[140px] radar-ring-glow" />

                <div className="radar-ring w-[280px] h-[280px] border-dashed border-white/[0.06] spin-slow" />

                <div className="radar-ring w-[420px] h-[420px] border-white/[0.04]" />

                <div className="radar-ring w-[520px] h-[520px] border-dashed border-cyan-500/10 spin-reverse-slow" />

                <div className="absolute top-0 bottom-0 left-1/2 w-px bg-gradient-to-b from-transparent via-white/[0.05] to-transparent" />

                <div className="absolute left-0 right-0 top-1/2 h-px bg-gradient-to-r from-transparent via-white/[0.05] to-transparent" />

                <div className="radar-beam" />

              </div>

              {/* Tag */}

              <div className="inline-flex items-center gap-2 px-3.5 py-1 rounded-full bg-white/[0.04] border border-white/[0.08] text-slate-300 text-[11px] font-mono tracking-widest uppercase mb-6 shadow-sm">

                <Lock className="w-3 h-3 text-cyan-400" />

                AUTONOMOUS ZERO-DAY PHISHING RADAR

              </div>

              {/* Title */}

              <h1 className="editorial-title text-6xl md:text-8xl lg:text-9xl font-black tracking-tight text-white mb-4">
                PHISHGUARD
              </h1>

              <p className="editorial-sub text-base md:text-xl font-bold tracking-[0.2em] text-cyan-300 mb-6 uppercase">
                "SEE THE THREAT BEFORE IT SEES YOU."
              </p>

              <p className="text-slate-400 text-sm md:text-base font-sans max-w-2xl mx-auto leading-relaxed mb-8">
                Enterprise-grade cybersecurity engine combining 24 lexical URL features, XGBoost machine learning classification, and Isolation Forest zero-day anomaly detection.
              </p>

              {/* URL INPUT */}

              <div className="max-w-3xl mx-auto">

                <div className="cyber-panel p-3 md:p-4 space-y-3">

                  <div className="flex flex-col sm:flex-row gap-2.5">

                    <div className="relative flex-grow">

                      <input
                        type="text"
                        value={urlInput}
                        onChange={(e) => setUrlInput(e.target.value)}
                        onKeyDown={(e) =>
                          e.key === 'Enter' && handleAnalyze()
                        }
                        placeholder="Paste a URL to analyze (e.g. http://paypal-security-update.xyz/login)..."
                        className="cyber-input w-full px-5 py-4 text-sm font-mono placeholder-slate-500 focus:text-white"
                      />

                      {urlInput && (

                        <button
                          onClick={() => setUrlInput('')}
                          className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 text-xs font-mono"
                        >
                          CLEAR
                        </button>

                      )}

                    </div>

                    <button
                      onClick={() => handleAnalyze()}
                      disabled={loading}
                      className="cyber-action-btn flex-shrink-0 justify-center text-xs font-mono"
                    >

                      {loading ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                          <span>ANALYZING...</span>
                        </>
                      ) : (
                        <span>
                          ANALYZE THREAT →
                        </span>
                      )}

                    </button>

                  </div>

                  {/* Quick Verification */}

                  <div className="flex items-center gap-2 flex-wrap pt-2 border-t border-white/[0.04]">

                    <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest font-semibold mr-1">
                      Quick Verification:
                    </span>

                    {SAMPLE_URLS.map((item, idx) => (

                      <button
                        key={idx}
                        onClick={() => {
                          setUrlInput(item.url);
                          handleAnalyze(item.url);
                        }}
                        className="quick-chip"
                      >
                        {item.label}
                      </button>

                    ))}

                  </div>

                </div>

              </div>

            </div>

            {/* ==================================================
                LOADING
            ================================================== */}

            {loading && (

              <div className="cyber-panel p-12 max-w-md mx-auto text-center space-y-6 my-8 cyber-panel-glow">

                <div className="relative w-32 h-32 mx-auto flex items-center justify-center">

                  <div className="absolute inset-0 rounded-full border border-cyan-500/30 animate-ping" />

                  <div className="absolute inset-2 rounded-full border border-dashed border-cyan-400/50 spin-slow" />

                  <div className="w-16 h-16 rounded-full bg-cyan-500/10 border border-cyan-400/60 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-500/30">

                    <Radio className="w-8 h-8 animate-pulse text-cyan-400" />

                  </div>

                </div>

                <div className="space-y-1">

                  <h3 className="font-mono text-base font-bold text-white tracking-wider">
                    SCANNING TARGET TELEMETRY
                  </h3>

                  <p className="text-[11px] font-mono text-slate-400">
                    Extracting 24 numerical vectors & computing Isolation Forest anomaly index...
                  </p>

                </div>

              </div>

            )}

            {/* ==================================================
                ERROR
            ================================================== */}

            {error && (

              <div className="max-w-2xl mx-auto p-5 rounded-2xl bg-rose-950/40 border border-rose-500/40 text-rose-200 space-y-2 shadow-2xl">

                <div className="flex items-center gap-3">

                  <AlertTriangle className="w-5 h-5 text-rose-400 flex-shrink-0" />

                  <h4 className="font-mono font-bold text-rose-300 text-sm tracking-wider">
                    ANALYSIS UNAVAILABLE
                  </h4>

                </div>

                <p className="text-xs text-rose-200/80 font-sans pl-8 leading-relaxed">
                  {error}
                </p>

              </div>

            )}

            {/* ==================================================
                RESULTS
            ================================================== */}

            {analysisResult && !loading && (

              <div className="space-y-8 animate-in fade-in duration-500">

                <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-white/[0.08] pb-4 gap-2">

                  <div className="flex items-center gap-2.5">

                    <Shield className="w-5 h-5 text-cyan-400" />

                    <h2 className="font-mono text-lg font-bold text-white tracking-wider">
                      THREAT TELEMETRY DOSSIER
                    </h2>

                  </div>

                  <div className="font-mono text-xs text-slate-400 truncate max-w-md bg-white/[0.03] px-3 py-1 rounded-lg border border-white/[0.06]">
                    {analysisResult.url}
                  </div>

                </div>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-5">

                  {/* Risk Score */}

                  <div className="cyber-panel p-6 flex flex-col items-center justify-center text-center space-y-3">

                    <span className="text-[11px] font-mono text-slate-400 uppercase tracking-widest font-semibold">
                      Composite Risk Index
                    </span>

                    <div className="relative w-36 h-36 flex items-center justify-center my-1">

                      <svg
                        className="w-full h-full transform -rotate-90"
                        viewBox="0 0 100 100"
                      >

                        <circle
                          cx="50"
                          cy="50"
                          r="40"
                          stroke="rgba(255,255,255,0.06)"
                          strokeWidth="7"
                          fill="transparent"
                        />

                        <circle
                          cx="50"
                          cy="50"
                          r="40"
                          stroke={
                            analysisResult.risk_score >= 85
                              ? '#ff2a5f'
                              : analysisResult.risk_score >= 60
                                ? '#ff6b00'
                                : analysisResult.risk_score >= 30
                                  ? '#eab308'
                                  : '#10b981'
                          }
                          strokeWidth="7"
                          strokeDasharray="251.2"
                          strokeDashoffset={
                            251.2 -
                            (251.2 *
                              analysisResult.risk_score) /
                            100
                          }
                          strokeLinecap="round"
                          fill="transparent"
                          className="transition-all duration-1000 ease-out"
                        />

                      </svg>

                      <div className="absolute inset-0 flex flex-col items-center justify-center">

                        <span className="editorial-title text-4xl font-extrabold text-white">
                          {analysisResult.risk_score}
                        </span>

                        <span className="text-[10px] text-slate-400 font-mono tracking-wider">
                          / 100
                        </span>

                      </div>

                    </div>

                    <div
                      className={`px-4 py-1 rounded-full text-[11px] font-mono font-bold tracking-widest ${getRiskBadgeClass(
                        analysisResult.risk_level
                      )}`}
                    >
                      {analysisResult.risk_level} RISK
                    </div>

                  </div>

                  {/* Phishing Probability */}

                  <div className="cyber-panel p-6 flex flex-col justify-between">

                    <div>

                      <span className="text-[11px] font-mono text-slate-400 uppercase tracking-widest font-semibold">
                        Phishing Probability
                      </span>

                      <h3 className="editorial-title text-4xl font-bold text-white mt-3">
                        {(
                          analysisResult.phishing_probability *
                          100
                        ).toFixed(1)}
                        %
                      </h3>

                      <p className="text-[11px] text-slate-400 mt-1 font-mono">
                        Model:{' '}
                        {analysisResult.model_used ||
                          'XGBoost'}
                      </p>

                    </div>

                    <div className="w-full bg-white/[0.05] rounded-full h-2 overflow-hidden mt-4">

                      <div
                        className={`h-full transition-all duration-1000 ${analysisResult.phishing_probability >=
                          0.5
                          ? 'bg-rose-500 shadow-sm shadow-rose-500'
                          : 'bg-emerald-400 shadow-sm shadow-emerald-400'
                          }`}
                        style={{
                          width: `${Math.min(
                            100,
                            Math.max(
                              2,
                              analysisResult.phishing_probability *
                              100
                            )
                          )}%`
                        }}
                      />

                    </div>

                  </div>

                  {/* Anomaly Score */}

                  <div className="cyber-panel p-6 flex flex-col justify-between">

                    <div>

                      <span className="text-[11px] font-mono text-slate-400 uppercase tracking-widest font-semibold">
                        Anomaly Score
                      </span>

                      <h3 className="editorial-title text-4xl font-bold text-cyan-400 mt-3">
                        {Number(
                          analysisResult.anomaly_score || 0
                        ).toFixed(2)}
                      </h3>

                      <p className="text-[11px] text-slate-400 mt-1 font-mono">
                        Isolation Forest Metric
                      </p>

                    </div>

                    <div className="w-full bg-white/[0.05] rounded-full h-2 overflow-hidden mt-4">

                      <div
                        className="h-full bg-cyan-400 shadow-sm shadow-cyan-400 transition-all duration-1000"
                        style={{
                          width: `${Math.min(
                            100,
                            Math.max(
                              2,
                              (analysisResult.anomaly_score || 0) *
                              100
                            )
                          )}%`
                        }}
                      />

                    </div>

                  </div>

                  {/* Classifier Verdict */}

                  <div className="cyber-panel p-6 flex flex-col justify-between">

                    <div>

                      <span className="text-[11px] font-mono text-slate-400 uppercase tracking-widest font-semibold">
                        Classifier Verdict
                      </span>

                      <div className="flex items-center gap-3 mt-3">

                        {String(
                          analysisResult.prediction
                        ).toLowerCase() === 'phishing' ||
                          analysisResult.prediction_code === 1 ? (

                          <ShieldAlert className="w-9 h-9 text-rose-500 flex-shrink-0" />

                        ) : (

                          <ShieldCheck className="w-9 h-9 text-emerald-400 flex-shrink-0" />

                        )}

                        <div>

                          <span
                            className={`editorial-title text-2xl font-bold ${String(
                              analysisResult.prediction
                            ).toLowerCase() === 'phishing' ||
                              analysisResult.prediction_code === 1
                              ? 'text-rose-400'
                              : 'text-emerald-400'
                              }`}
                          >
                            {String(
                              analysisResult.prediction ||
                              analysisResult.prediction_label ||
                              'UNKNOWN'
                            ).toUpperCase()}
                          </span>

                          <p className="text-[10px] text-slate-400 font-mono">
                            Deterministic ML Output
                          </p>

                        </div>

                      </div>

                    </div>

                    <button
                      onClick={() => setChatOpen(true)}
                      className="text-xs font-mono font-bold text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 mt-4 transition-colors"
                    >
                      <MessageSquare className="w-3.5 h-3.5" />
                      Ask PHISHGUARD AI about this link
                    </button>

                  </div>

                </div>

                {/* Recommendation */}

                {(() => {

                  const rec = getRecommendation(
                    analysisResult.risk_level
                  );

                  return (

                    <div
                      className={`p-5 rounded-2xl border flex items-start gap-4 ${rec.type === 'danger'
                        ? 'bg-rose-950/20 border-rose-500/30 text-rose-200'
                        : rec.type === 'warning'
                          ? 'bg-amber-950/20 border-amber-500/30 text-amber-200'
                          : 'bg-emerald-950/20 border-emerald-500/30 text-emerald-200'
                        }`}
                    >

                      {rec.type === 'danger' ? (

                        <ShieldAlert className="w-6 h-6 text-rose-400 flex-shrink-0 mt-0.5" />

                      ) : rec.type === 'warning' ? (

                        <AlertTriangle className="w-6 h-6 text-amber-400 flex-shrink-0 mt-0.5" />

                      ) : (

                        <ShieldCheck className="w-6 h-6 text-emerald-400 flex-shrink-0 mt-0.5" />

                      )}

                      <div>

                        <h4 className="font-mono font-bold text-sm tracking-wide">
                          {rec.title}
                        </h4>

                        <p className="text-xs mt-1 text-slate-300 font-sans leading-relaxed">
                          {rec.desc}
                        </p>

                      </div>

                    </div>

                  );

                })()}

                {/* Why Flagged */}

                <div className="cyber-panel p-6 space-y-4">

                  <div className="flex items-center gap-2">

                    <Info className="w-4 h-4 text-cyan-400" />

                    <h3 className="font-mono text-sm font-bold text-white tracking-wider uppercase">
                      WHY THIS URL WAS FLAGGED
                    </h3>

                  </div>

                  <div className="space-y-2.5">

                    {analysisResult.reasons &&
                      analysisResult.reasons.length > 0 ? (

                      analysisResult.reasons.map(
                        (reason, idx) => (

                          <div
                            key={idx}
                            className="p-3.5 rounded-xl bg-white/[0.02] border border-white/[0.06] flex items-start gap-3 text-xs text-slate-200"
                          >

                            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 flex-shrink-0 shadow-sm shadow-cyan-400" />

                            <span className="font-sans leading-relaxed">
                              {reason}
                            </span>

                          </div>

                        )
                      )

                    ) : (

                      <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/[0.06] text-xs text-slate-400 font-mono">
                        No active threat flags detected. Domain matches clean baseline parameters.
                      </div>

                    )}

                  </div>

                </div>

                {/* Extracted Features */}

                {analysisResult.features && (

                  <div className="cyber-panel p-6 space-y-4">

                    <div className="flex items-center gap-2">

                      <BarChart3 className="w-4 h-4 text-cyan-400" />

                      <h3 className="font-mono text-sm font-bold text-white tracking-wider uppercase">
                        EXTRACTED LEXICAL FEATURES
                      </h3>

                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">

                      <FeatureBox
                        label="URL Length"
                        value={`${analysisResult.features.URLLength} chars`}
                      />

                      <FeatureBox
                        label="Domain Length"
                        value={`${analysisResult.features.DomainLength} chars`}
                      />

                      <FeatureBox
                        label="Subdomains"
                        value={analysisResult.features.NoOfSubDomain}
                      />

                      <FeatureBox
                        label="TLD Length"
                        value={analysisResult.features.TLDLength}
                      />

                      <FeatureBox
                        label="HTTPS Protocol"
                        value={
                          analysisResult.features.IsHTTPS === 1
                            ? 'YES'
                            : 'NO (Insecure)'
                        }
                        highlight={
                          analysisResult.features.IsHTTPS === 0
                        }
                      />

                      <FeatureBox
                        label="IP Usage"
                        value={
                          analysisResult.features.IsDomainIP === 1
                            ? 'YES (Suspicious)'
                            : 'NO'
                        }
                        highlight={
                          analysisResult.features.IsDomainIP === 1
                        }
                      />

                      <FeatureBox
                        label="Entropy"
                        value={Number(
                          analysisResult.features.Entropy || 0
                        ).toFixed(2)}
                      />

                      <FeatureBox
                        label="Suspicious Keywords"
                        value={
                          analysisResult.features.SuspiciousKeywordCount
                        }
                        highlight={
                          analysisResult.features.SuspiciousKeywordCount > 0
                        }
                      />

                    </div>

                  </div>

                )}

              </div>

            )}

          </div>

        )}

        {/* ====================================================
            MODEL INTELLIGENCE
        ==================================================== */}

        {activeTab === 'intelligence' && (

          <div className="space-y-10 animate-in fade-in duration-500">

            <div className="space-y-2">

              <span className="text-[11px] font-mono text-cyan-400 uppercase tracking-widest font-bold">
                TELEMETRY & MODEL PERFORMANCE
              </span>

              <h2 className="editorial-title text-4xl md:text-5xl font-black text-white">
                MODEL INTELLIGENCE & EMPIRICAL METRICS
              </h2>

              <p className="text-slate-400 text-sm font-sans max-w-3xl leading-relaxed">
                Trained on 235,795 records from the PhiUSIIL Phishing URL Dataset. The machine learning pipeline utilizes stratified 80/20 train-test splits and an Isolation Forest structural anomaly detector.
              </p>

            </div>

            {/* Classifier Comparison */}

            {metricsData &&
              metricsData.metrics && (

                <div className="cyber-panel p-6 space-y-4">

                  <div className="flex items-center gap-2">

                    <Activity className="w-4 h-4 text-cyan-400" />

                    <h3 className="font-mono text-sm font-bold text-white tracking-wider uppercase">
                      CLASSIFIER PERFORMANCE BENCHMARK
                    </h3>

                  </div>

                  <div className="overflow-x-auto">

                    <table className="w-full text-left border-collapse text-xs font-mono">

                      <thead>

                        <tr className="border-b border-white/[0.08] text-slate-400 uppercase tracking-wider">

                          <th className="p-3">
                            Model Architecture
                          </th>

                          <th className="p-3">
                            Accuracy
                          </th>

                          <th className="p-3">
                            Precision
                          </th>

                          <th className="p-3">
                            Recall
                          </th>

                          <th className="p-3">
                            F1 Score
                          </th>

                          <th className="p-3">
                            ROC-AUC
                          </th>

                          <th className="p-3">
                            Status
                          </th>

                        </tr>

                      </thead>

                      <tbody className="divide-y divide-white/[0.04]">

                        {Object.entries(
                          metricsData.metrics
                        ).map(([name, m], idx) => (

                          <tr
                            key={idx}
                            className={
                              name === metricsData.best_model
                                ? 'bg-cyan-500/[0.06]'
                                : ''
                            }
                          >

                            <td className="p-3 text-white font-bold">

                              <div className="flex items-center gap-2">

                                {name}

                                {name ===
                                  metricsData.best_model && (

                                    <span className="text-[9px] bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 px-2 py-0.5 rounded font-mono font-bold tracking-wider">
                                      SELECTED BEST
                                    </span>

                                  )}

                              </div>

                            </td>

                            <td className="p-3 text-slate-200">
                              {(m.Accuracy * 100).toFixed(2)}%
                            </td>

                            <td className="p-3 text-slate-200">
                              {(m.Precision * 100).toFixed(2)}%
                            </td>

                            <td className="p-3 text-slate-200">
                              {(m.Recall * 100).toFixed(2)}%
                            </td>

                            <td className="p-3 text-cyan-400 font-bold">
                              {(m.F1_Score * 100).toFixed(2)}%
                            </td>

                            <td className="p-3 text-emerald-400 font-bold">
                              {m.ROC_AUC.toFixed(4)}
                            </td>

                            <td className="p-3 text-slate-400">
                              ARTIFACT LOADED
                            </td>

                          </tr>

                        ))}

                      </tbody>

                    </table>

                  </div>

                </div>

              )}

            {/* Visual Analytics */}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

              <VisualPlotCard
                title="Confusion Matrix (Best Model)"
                imageSrc="/static/results/confusion_matrix.png"
              />

              <VisualPlotCard
                title="ROC Curve Comparison"
                imageSrc="/static/results/roc_curve.png"
              />

              <VisualPlotCard
                title="Top XGBoost Feature Importances"
                imageSrc="/static/results/feature_importance.png"
              />

              <VisualPlotCard
                title="Isolation Forest Anomaly Distribution"
                imageSrc="/static/results/anomaly_visual.png"
              />

            </div>

          </div>

        )}

      </main>

      {/* ======================================================
          PHISHGUARD AI DRAWER
      ====================================================== */}

      {chatOpen && (

        <div className="fixed bottom-6 right-6 w-96 max-w-[calc(100vw-3rem)] h-[560px] cyber-panel flex flex-col z-50 shadow-2xl shadow-cyan-500/10 animate-in slide-in-from-bottom-5 duration-300 border border-cyan-500/30">

          {/* Header */}

          <div className="p-4 border-b border-white/[0.08] bg-[#07090f] flex items-center justify-between">

            <div className="flex items-center gap-2">

              <Shield className="w-4 h-4 text-cyan-400" />

              <div>

                <h4 className="font-mono text-xs font-bold text-white tracking-wider">
                  PHISHGUARD AI ANALYST
                </h4>

                <span className="text-[10px] text-slate-400 font-mono">
                  Real-Time Threat Intelligence
                </span>

              </div>

            </div>

            <button
              onClick={() => setChatOpen(false)}
              className="text-slate-400 hover:text-white text-xs font-mono p-1 rounded hover:bg-white/[0.06]"
            >
              ✕
            </button>

          </div>

          {/* Messages */}

          <div className="flex-grow p-4 overflow-y-auto space-y-3 font-sans text-xs">

            {chatMessages.map((msg, idx) => (

              <div
                key={idx}
                className={`flex flex-col ${msg.sender === 'user'
                  ? 'items-end'
                  : 'items-start'
                  }`}
              >

                <div
                  className={`p-3.5 rounded-2xl max-w-[90%] ${msg.sender === 'user'
                    ? 'bg-cyan-500/15 border border-cyan-500/30 text-cyan-100'
                    : 'bg-white/[0.04] border border-white/[0.08] text-slate-200'
                    }`}
                >

                  <div className="whitespace-pre-wrap leading-relaxed">
                    {msg.text}
                  </div>

                  {msg.engine && (

                    <div className="text-[10px] text-slate-500 font-mono mt-1.5 pt-1 border-t border-white/[0.06]">
                      Engine: {msg.engine}
                    </div>

                  )}

                </div>

              </div>

            ))}

            {chatLoading && (

              <div className="text-cyan-400 font-mono text-[11px] animate-pulse flex items-center gap-2">

                <RefreshCw className="w-3 h-3 animate-spin" />

                Evaluating threat telemetry...

              </div>

            )}

          </div>

          {/* Quick prompts */}

          <div className="px-3 py-2 border-t border-white/[0.06] bg-black/40 flex items-center gap-1.5 overflow-x-auto text-[11px] font-mono">

            <button
              onClick={() =>
                handleSendChat(
                  'Why was this URL flagged?'
                )
              }
              className="px-2.5 py-1 rounded-full bg-white/[0.04] border border-white/[0.08] hover:border-cyan-400 text-slate-300 flex-shrink-0 transition-colors"
            >
              Why flagged?
            </button>

            <button
              onClick={() =>
                handleSendChat(
                  'What should I do?'
                )
              }
              className="px-2.5 py-1 rounded-full bg-white/[0.04] border border-white/[0.08] hover:border-cyan-400 text-slate-300 flex-shrink-0 transition-colors"
            >
              What should I do?
            </button>

            <button
              onClick={() =>
                handleSendChat(
                  'Explain the anomaly score'
                )
              }
              className="px-2.5 py-1 rounded-full bg-white/[0.04] border border-white/[0.08] hover:border-cyan-400 text-slate-300 flex-shrink-0 transition-colors"
            >
              Explain anomaly score
            </button>

            <button
              onClick={() =>
                handleSendChat(
                  'Is this URL safe?'
                )
              }
              className="px-2.5 py-1 rounded-full bg-white/[0.04] border border-white/[0.08] hover:border-cyan-400 text-slate-300 flex-shrink-0 transition-colors"
            >
              Is URL safe?
            </button>

          </div>

          {/* Chat input */}

          <div className="p-3 border-t border-white/[0.08] bg-[#07090f] flex gap-2">

            <input
              type="text"
              value={chatInput}
              onChange={(e) =>
                setChatInput(e.target.value)
              }
              onKeyDown={(e) =>
                e.key === 'Enter' &&
                handleSendChat()
              }
              placeholder="Ask security analyst advice..."
              className="flex-grow bg-white/[0.03] border border-white/[0.1] rounded-xl px-3 py-2 text-slate-100 text-xs font-sans focus:outline-none focus:border-cyan-400"
            />

            <button
              onClick={() => handleSendChat()}
              disabled={chatLoading}
              className="p-2 rounded-xl bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 flex-shrink-0 transition-colors"
            >
              <Send className="w-4 h-4" />
            </button>

          </div>

        </div>

      )}

    </div>
  );
}

// ============================================================
// FEATURE BOX
// ============================================================

function FeatureBox({
  label,
  value,
  highlight = false
}) {
  return (
    <div
      className={`p-3.5 rounded-xl border text-left ${highlight
        ? 'bg-rose-950/20 border-rose-500/40 text-rose-200'
        : 'bg-white/[0.02] border-white/[0.06] text-slate-300'
        }`}
    >

      <div className="text-[10px] text-slate-400 font-mono uppercase tracking-wider font-semibold">
        {label}
      </div>

      <div className="font-mono text-xs font-bold mt-1 text-slate-100">
        {value}
      </div>

    </div>
  );
}

// ============================================================
// VISUAL PLOT CARD
// ============================================================

function VisualPlotCard({
  title,
  imageSrc
}) {
  return (
    <div className="cyber-panel p-5 space-y-3">

      <h4 className="font-mono text-xs font-bold text-slate-200 tracking-wider uppercase">
        {title}
      </h4>

      <div className="rounded-xl overflow-hidden border border-white/[0.06] bg-black/40 flex items-center justify-center p-2">

        <img
          src={imageSrc}
          alt={title}
          className="w-full h-auto object-contain max-h-72"
          onError={(e) => {
            e.target.style.display = 'none';
          }}
        />

      </div>

    </div>
  );
}
