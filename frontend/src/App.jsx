import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, ShieldCheck, Zap, BarChart3, MessageSquare, AlertTriangle, 
  ExternalLink, Cpu, Activity, Info, RefreshCw, Send, CheckCircle2, Lock, ArrowRight
} from 'lucide-react';

// Sample URLs for 1-click test
const SAMPLE_URLS = [
  { label: 'Legitimate Github', url: 'https://github.com/torvalds/linux' },
  { label: 'Phishing PayPal Spoof', url: 'http://paypal-security-update.xyz/login?id=99283' },
  { label: 'Suspicious IP Host', url: 'http://192.168.1.1/admin/login' },
  { label: 'Obfuscated @ Redirect', url: 'http://login.bank.com@secure-verify-update.info/auth' }
];

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [error, setError] = useState(null);
  const [backendHealth, setBackendHealth] = useState(null);
  const [metricsData, setMetricsData] = useState(null);

  // Chat state
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState([
    { sender: 'ai', text: 'Greetings Agent. I am PHISHGUARD AI. Enter a URL above to begin threat analysis or ask me any cybersecurity questions.' }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);

  // Check health and load metrics on mount
  useEffect(() => {
    fetchHealth();
    fetchMetrics();
  }, []);

  const fetchHealth = async () => {
    try {
      const res = await fetch('/api/health');
      if (res.ok) {
        const data = await res.json();
        setBackendHealth(data);
      } else {
        setBackendHealth({ status: 'offline' });
      }
    } catch {
      setBackendHealth({ status: 'offline' });
    }
  };

  const fetchMetrics = async () => {
    try {
      const res = await fetch('/api/metrics');
      if (res.ok) {
        const data = await res.json();
        setMetricsData(data);
      }
    } catch (e) {
      console.error('Failed to fetch metrics', e);
    }
  };

  const handleAnalyze = async (targetUrl = urlInput) => {
    const urlToTest = targetUrl || urlInput;
    if (!urlToTest || !urlToTest.trim()) return;

    setLoading(true);
    setError(null);
    setAnalysisResult(null);

    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlToTest.trim() })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || 'Analysis request failed.');
      }

      const data = await res.json();
      setAnalysisResult(data);

      // Auto notify chatbot context
      setChatMessages(prev => [
        ...prev,
        { 
          sender: 'ai', 
          text: `Scan complete for \`${data.url}\`. Risk Level: **${data.risk_level}** (${data.risk_score}/100). Ask me anything about this scan.`
        }
      ]);
    } catch (err) {
      setError(err.message || 'Error connecting to backend server.');
    } finally {
      setLoading(false);
    }
  };

  const handleSendChat = async (queryText = chatInput) => {
    const textToSend = queryText || chatInput;
    if (!textToSend || !textToSend.trim()) return;

    const newMsgs = [...chatMessages, { sender: 'user', text: textToSend }];
    setChatMessages(newMsgs);
    setChatInput('');
    setChatLoading(true);

    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: textToSend,
          context: analysisResult
        })
      });

      if (res.ok) {
        const data = await res.json();
        setChatMessages(prev => [
          ...prev, 
          { sender: 'ai', text: data.response, engine: data.engine }
        ]);
      } else {
        setChatMessages(prev => [
          ...prev, 
          { sender: 'ai', text: 'Unable to process chat request at this time.' }
        ]);
      }
    } catch {
      setChatMessages(prev => [
        ...prev, 
        { sender: 'ai', text: 'Error contacting PhishGuard AI service.' }
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  const getRiskBadgeClass = (level) => {
    switch (level) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      case 'LOW': return 'badge-low';
      default: return 'badge-low';
    }
  };

  return (
    <div className="min-h-screen flex flex-col relative pb-20">
      {/* Top Header */}
      <header className="border-b border-cyan-500/20 bg-slate-950/80 backdrop-blur-md sticky top-0 z-40 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-400/30 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-500/20">
              <Zap className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h1 className="font-orbitron text-xl font-black tracking-wider text-white flex items-center gap-2">
                PHISH<span className="text-cyan-400">GUARD</span>
                <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-rajdhani border border-cyan-500/30">v1.0 ML</span>
              </h1>
              <p className="text-xs text-slate-400 font-rajdhani uppercase tracking-widest">URL Cyber Threat Intelligence Engine</p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex items-center gap-2 bg-slate-900/90 border border-slate-800 p-1.5 rounded-xl">
            <button 
              onClick={() => setActiveTab('scanner')}
              className={`px-4 py-2 rounded-lg text-sm font-rajdhani font-semibold transition-all flex items-center gap-2 ${
                activeTab === 'scanner' 
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/20' 
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Activity className="w-4 h-4" /> URL Scanner
            </button>
            <button 
              onClick={() => setActiveTab('intelligence')}
              className={`px-4 py-2 rounded-lg text-sm font-rajdhani font-semibold transition-all flex items-center gap-2 ${
                activeTab === 'intelligence' 
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/20' 
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Cpu className="w-4 h-4" /> Model Intelligence
            </button>
          </nav>

          {/* System Health Badge */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 text-xs font-rajdhani px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800">
              <span className={`w-2 h-2 rounded-full ${backendHealth?.status === 'healthy' ? 'bg-emerald-400 shadow-lg shadow-emerald-500/50 animate-ping' : 'bg-rose-500'}`} />
              <span className="text-slate-300">SYSTEM:</span>
              <span className={backendHealth?.status === 'healthy' ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                {backendHealth?.status === 'healthy' ? 'ONLINE (ML LOADED)' : 'OFFLINE'}
              </span>
            </div>
            
            <button 
              onClick={() => setChatOpen(!chatOpen)}
              className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 transition-all relative"
              title="PhishGuard AI Assistant"
            >
              <MessageSquare className="w-5 h-5" />
              <span className="absolute -top-1 -right-1 w-3 h-3 bg-cyan-400 rounded-full border-2 border-slate-950 animate-pulse" />
            </button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-6 pt-10 w-full flex-grow">
        {activeTab === 'scanner' && (
          <div className="space-y-10">
            {/* Hero Banner */}
            <div className="text-center space-y-4 max-w-3xl mx-auto">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-rajdhani font-semibold tracking-wider uppercase">
                <Lock className="w-3.5 h-3.5" /> Next-Gen ML Phishing Detection
              </div>
              <h2 className="font-orbitron text-4xl md:text-5xl font-black tracking-tight text-white glow-cyan">
                REAL-TIME URL THREAT ANALYSIS
              </h2>
              <p className="text-slate-400 text-base font-sans">
                Inspect web links using XGBoost classification, Isolation Forest anomaly scoring, and 20+ lexical feature extractions under 5 milliseconds.
              </p>
            </div>

            {/* URL Input Box */}
            <div className="max-w-4xl mx-auto">
              <div className="cyber-card p-4 md:p-6 space-y-4">
                <div className="flex flex-col md:flex-row gap-3">
                  <div className="relative flex-grow">
                    <input 
                      type="text" 
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleAnalyze()}
                      placeholder="Paste suspect URL (e.g. http://login-paypal-verify.xyz/account)..."
                      className="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-5 py-4 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all font-mono text-sm"
                    />
                    {urlInput && (
                      <button 
                        onClick={() => setUrlInput('')}
                        className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 text-xs"
                      >
                        CLEAR
                      </button>
                    )}
                  </div>

                  <button 
                    onClick={() => handleAnalyze()}
                    disabled={loading}
                    className="cyber-btn justify-center text-sm font-orbitron"
                  >
                    {loading ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" /> SCANNING...
                      </>
                    ) : (
                      <>
                        ANALYZE TARGET <ArrowRight className="w-4 h-4" />
                      </>
                    )}
                  </button>
                </div>

                {/* Sample Chips */}
                <div className="flex items-center gap-2 flex-wrap pt-2">
                  <span className="text-xs font-rajdhani text-slate-500 uppercase tracking-wider font-semibold">Quick Samples:</span>
                  {SAMPLE_URLS.map((sample, idx) => (
                    <button 
                      key={idx}
                      onClick={() => {
                        setUrlInput(sample.url);
                        handleAnalyze(sample.url);
                      }}
                      className="sample-pill font-mono text-xs"
                    >
                      {sample.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Loading Radar Animation State */}
            {loading && (
              <div className="cyber-card p-12 max-w-xl mx-auto text-center space-y-6">
                <div className="relative w-36 h-36 mx-auto flex items-center justify-center">
                  <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20 scanner-pulse" />
                  <div className="absolute inset-2 rounded-full border border-dashed border-cyan-500/40 radar-spinner" />
                  <div className="w-16 h-16 rounded-full bg-cyan-500/10 border border-cyan-400/50 flex items-center justify-center text-cyan-400">
                    <Zap className="w-8 h-8 animate-bounce" />
                  </div>
                </div>
                <div className="space-y-2">
                  <h3 className="font-orbitron text-lg font-bold text-white tracking-wider">NEURAL SCAN IN PROGRESS</h3>
                  <p className="text-xs font-rajdhani text-cyan-400 animate-pulse">Extracting 24 URL lexical vectors & calculating Isolation Forest anomaly score...</p>
                </div>
              </div>
            )}

            {/* Error Message */}
            {error && (
              <div className="max-w-2xl mx-auto p-4 rounded-xl bg-rose-950/60 border border-rose-500/40 text-rose-300 flex items-center gap-3">
                <AlertTriangle className="w-6 h-6 flex-shrink-0 text-rose-400" />
                <span className="text-sm font-sans">{error}</span>
              </div>
            )}

            {/* Analysis Result View */}
            {analysisResult && !loading && (
              <div className="space-y-8 animate-in fade-in duration-500">
                {/* Top Summary Cards */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                  {/* Gauge Risk Score Card */}
                  <div className="cyber-card p-6 flex flex-col items-center justify-center text-center space-y-3">
                    <span className="text-xs font-rajdhani text-slate-400 uppercase tracking-widest font-semibold">Composite Risk Score</span>
                    
                    <div className="relative w-32 h-32 flex items-center justify-center">
                      <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                        <circle cx="50" cy="50" r="40" stroke="rgba(255,255,255,0.08)" strokeWidth="8" fill="transparent" />
                        <circle 
                          cx="50" cy="50" r="40" 
                          stroke={analysisResult.risk_score >= 85 ? '#ff2a5f' : analysisResult.risk_score >= 60 ? '#ff7700' : analysisResult.risk_score >= 30 ? '#ffcc00' : '#00ff88'}
                          strokeWidth="8" 
                          strokeDasharray={251.2}
                          strokeDashoffset={251.2 - (251.2 * analysisResult.risk_score) / 100}
                          strokeLinecap="round"
                          fill="transparent" 
                          className="transition-all duration-1000 ease-out"
                        />
                      </svg>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span className="font-orbitron text-3xl font-black text-white">{analysisResult.risk_score}</span>
                        <span className="text-[10px] text-slate-400 font-mono">/ 100</span>
                      </div>
                    </div>

                    <div className={`px-4 py-1 rounded-full text-xs font-orbitron font-bold tracking-widest ${getRiskBadgeClass(analysisResult.risk_level)}`}>
                      {analysisResult.risk_level} RISK
                    </div>
                  </div>

                  {/* ML Phishing Probability */}
                  <div className="cyber-card p-6 flex flex-col justify-between">
                    <div>
                      <span className="text-xs font-rajdhani text-slate-400 uppercase tracking-widest font-semibold">ML Phishing Probability</span>
                      <h3 className="font-orbitron text-3xl font-bold text-white mt-2">
                        {(analysisResult.phishing_probability * 100).toFixed(1)}%
                      </h3>
                      <p className="text-xs text-slate-400 mt-1 font-mono">Classifier: {analysisResult.model_used}</p>
                    </div>

                    <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800 mt-4">
                      <div 
                        className={`h-full transition-all duration-1000 ${analysisResult.phishing_probability >= 0.5 ? 'bg-rose-500' : 'bg-emerald-400'}`}
                        style={{ width: `${analysisResult.phishing_probability * 100}%` }}
                      />
                    </div>
                  </div>

                  {/* Isolation Forest Anomaly Index */}
                  <div className="cyber-card p-6 flex flex-col justify-between">
                    <div>
                      <span className="text-xs font-rajdhani text-slate-400 uppercase tracking-widest font-semibold">Anomaly Index</span>
                      <h3 className="font-orbitron text-3xl font-bold text-cyan-400 mt-2">
                        {analysisResult.anomaly_score.toFixed(2)}
                      </h3>
                      <p className="text-xs text-slate-400 mt-1 font-mono">Isolation Forest Model</p>
                    </div>

                    <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800 mt-4">
                      <div 
                        className="h-full bg-cyan-400 transition-all duration-1000"
                        style={{ width: `${analysisResult.anomaly_score * 100}%` }}
                      />
                    </div>
                  </div>

                  {/* Model Verdict Card */}
                  <div className="cyber-card p-6 flex flex-col justify-between">
                    <div>
                      <span className="text-xs font-rajdhani text-slate-400 uppercase tracking-widest font-semibold">Target Classification</span>
                      <div className="flex items-center gap-3 mt-3">
                        {analysisResult.prediction === 1 ? (
                          <ShieldAlert className="w-8 h-8 text-rose-500" />
                        ) : (
                          <ShieldCheck className="w-8 h-8 text-emerald-400" />
                        )}
                        <div>
                          <span className={`font-orbitron text-xl font-bold ${analysisResult.prediction === 1 ? 'text-rose-400' : 'text-emerald-400'}`}>
                            {analysisResult.prediction_label.toUpperCase()}
                          </span>
                          <p className="text-[11px] text-slate-400">Deterministic ML Output</p>
                        </div>
                      </div>
                    </div>

                    <button 
                      onClick={() => setChatOpen(true)}
                      className="text-xs font-rajdhani text-cyan-400 hover:underline flex items-center gap-1 mt-4"
                    >
                      <MessageSquare className="w-3.5 h-3.5" /> Ask AI why this link was flagged
                    </button>
                  </div>
                </div>

                {/* Flagged Reasons Section */}
                <div className="cyber-card p-6 space-y-4">
                  <h3 className="font-orbitron text-lg font-bold text-white flex items-center gap-2">
                    <Info className="w-5 h-5 text-cyan-400" /> THREAT EVALUATION & REASONS
                  </h3>
                  
                  <div className="space-y-2.5">
                    {analysisResult.reasons.map((reason, idx) => (
                      <div 
                        key={idx}
                        className="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800/80 flex items-start gap-3 text-sm text-slate-200"
                      >
                        <span className="w-2 h-2 rounded-full bg-cyan-400 mt-2 flex-shrink-0" />
                        <span>{reason}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Extracted Features Grid */}
                <div className="cyber-card p-6 space-y-4">
                  <h3 className="font-orbitron text-lg font-bold text-white flex items-center gap-2">
                    <BarChart3 className="w-5 h-5 text-cyan-400" /> EXTRACTED LEXICAL FEATURES
                  </h3>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <FeatureBox label="URL Length" value={`${analysisResult.features.URLLength} chars`} />
                    <FeatureBox label="Domain Length" value={`${analysisResult.features.DomainLength} chars`} />
                    <FeatureBox label="Subdomain Count" value={analysisResult.features.NoOfSubDomain} />
                    <FeatureBox label="TLD Length" value={analysisResult.features.TLDLength} />
                    <FeatureBox label="HTTPS Protocol" value={analysisResult.features.IsHTTPS === 1 ? 'YES' : 'NO (Insecure)'} highlight={analysisResult.features.IsHTTPS === 0} />
                    <FeatureBox label="IP Usage" value={analysisResult.features.IsDomainIP === 1 ? 'YES (Suspicious)' : 'NO'} highlight={analysisResult.features.IsDomainIP === 1} />
                    <FeatureBox label="Entropy" value={analysisResult.features.Entropy.toFixed(2)} />
                    <FeatureBox label="Suspicious Keywords" value={analysisResult.features.SuspiciousKeywordCount} highlight={analysisResult.features.SuspiciousKeywordCount > 0} />
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Model Intelligence Tab */}
        {activeTab === 'intelligence' && (
          <div className="space-y-8 animate-in fade-in duration-500">
            <div className="text-center space-y-2">
              <h2 className="font-orbitron text-3xl font-bold text-white glow-cyan">MODEL INTELLIGENCE & BENCHMARKS</h2>
              <p className="text-slate-400 text-sm">Trained on 235,795 PhiUSIIL Phishing URL Dataset records with 80/20 stratified validation.</p>
            </div>

            {/* Metrics Comparison Table */}
            {metricsData && (
              <div className="cyber-card p-6 space-y-4">
                <h3 className="font-orbitron text-lg font-bold text-white flex items-center gap-2">
                  <Activity className="w-5 h-5 text-cyan-400" /> MODEL PERFORMANCE MATRIX
                </h3>

                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse font-sans text-sm">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400 font-rajdhani text-xs uppercase tracking-wider">
                        <th className="p-3">Model Architecture</th>
                        <th className="p-3">Accuracy</th>
                        <th className="p-3">Precision</th>
                        <th className="p-3">Recall</th>
                        <th className="p-3">F1 Score</th>
                        <th className="p-3">ROC-AUC</th>
                        <th className="p-3">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {Object.entries(metricsData.metrics).map(([modelName, m], idx) => (
                        <tr key={idx} className={modelName === metricsData.best_model ? 'bg-cyan-500/10' : ''}>
                          <td className="p-3 font-orbitron font-bold text-white flex items-center gap-2">
                            {modelName}
                            {modelName === metricsData.best_model && (
                              <span className="text-[10px] bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded font-rajdhani">SELECTED BEST</span>
                            )}
                          </td>
                          <td className="p-3 font-mono text-slate-200">{(m.Accuracy * 100).toFixed(2)}%</td>
                          <td className="p-3 font-mono text-slate-200">{(m.Precision * 100).toFixed(2)}%</td>
                          <td className="p-3 font-mono text-slate-200">{(m.Recall * 100).toFixed(2)}%</td>
                          <td className="p-3 font-mono font-bold text-cyan-400">{(m.F1_Score * 100).toFixed(2)}%</td>
                          <td className="p-3 font-mono text-emerald-400 font-bold">{m.ROC_AUC.toFixed(4)}</td>
                          <td className="p-3 text-xs font-rajdhani text-slate-400">TRAINED & SAVED</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Embedded Visualization Plots */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <VisualPlotCard title="Confusion Matrix (Best Model)" imageSrc="/static/results/confusion_matrix.png" />
              <VisualPlotCard title="ROC Curve Comparison" imageSrc="/static/results/roc_curve.png" />
              <VisualPlotCard title="Top XGBoost Feature Importances" imageSrc="/static/results/feature_importance.png" />
              <VisualPlotCard title="Isolation Forest Anomaly Score Distribution" imageSrc="/static/results/anomaly_visual.png" />
            </div>
          </div>
        )}
      </main>

      {/* Floating PhishGuard AI Chat Drawer */}
      {chatOpen && (
        <div className="fixed bottom-6 right-6 w-96 max-w-[calc(100vw-3rem)] h-[520px] cyber-card flex flex-col z-50 shadow-2xl shadow-cyan-500/20 animate-in slide-in-from-bottom-5 duration-300">
          {/* Chat Header */}
          <div className="p-4 border-b border-slate-800 bg-slate-950/90 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Zap className="w-5 h-5 text-cyan-400" />
              <h4 className="font-orbitron text-sm font-bold text-white">PHISHGUARD AI</h4>
            </div>
            <button onClick={() => setChatOpen(false)} className="text-slate-400 hover:text-white text-xs">
              ✕
            </button>
          </div>

          {/* Chat Body */}
          <div className="flex-grow p-4 overflow-y-auto space-y-3 font-sans text-xs">
            {chatMessages.map((msg, idx) => (
              <div key={idx} className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'}`}>
                <div className={`p-3 rounded-xl max-w-[85%] ${
                  msg.sender === 'user' 
                    ? 'bg-cyan-500/20 border border-cyan-500/40 text-cyan-100' 
                    : 'bg-slate-900 border border-slate-800 text-slate-200'
                }`}>
                  <div className="whitespace-pre-wrap">{msg.text}</div>
                  {msg.engine && (
                    <div className="text-[10px] text-slate-500 font-mono mt-1 pt-1 border-t border-slate-800">
                      Engine: {msg.engine}
                    </div>
                  )}
                </div>
              </div>
            ))}
            {chatLoading && (
              <div className="text-cyan-400 font-mono text-[11px] animate-pulse">Analyzing security context...</div>
            )}
          </div>

          {/* Chat Input */}
          <div className="p-3 border-t border-slate-800 bg-slate-950/90 flex gap-2">
            <input 
              type="text" 
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSendChat()}
              placeholder="Ask why flagged, action steps..."
              className="flex-grow bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-slate-100 text-xs focus:outline-none focus:border-cyan-400"
            />
            <button 
              onClick={() => handleSendChat()}
              disabled={chatLoading}
              className="p-2 rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30"
            >
              <Send className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function FeatureBox({ label, value, highlight = false }) {
  return (
    <div className={`p-3 rounded-lg border text-left ${highlight ? 'bg-rose-950/30 border-rose-500/40 text-rose-300' : 'bg-slate-900/60 border-slate-800/80 text-slate-300'}`}>
      <div className="text-[11px] text-slate-500 font-rajdhani font-semibold uppercase">{label}</div>
      <div className="font-mono text-sm font-bold mt-0.5">{value}</div>
    </div>
  );
}

function VisualPlotCard({ title, imageSrc }) {
  return (
    <div className="cyber-card p-4 space-y-3">
      <h4 className="font-orbitron text-sm font-bold text-slate-200">{title}</h4>
      <div className="rounded-lg overflow-hidden border border-slate-800 bg-slate-950 flex items-center justify-center p-2">
        <img src={imageSrc} alt={title} className="w-full h-auto object-contain max-h-72" />
      </div>
    </div>
  );
}
