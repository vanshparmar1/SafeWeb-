import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, Scan, Layers, Brain, Globe, Search, X, Loader2, 
  Sparkles, AlertOctagon, CheckCircle2, ChevronDown, Cpu, FileCode,
  Shield, ExternalLink
} from 'lucide-react';
import ScoreGauge from './components/ScoreGauge';
import VerdictBanner from './components/VerdictBanner';
import BatchScanner from './components/BatchScanner';
import ModelIntelligence from './components/ModelIntelligence';

const API_BASE = import.meta.env.VITE_API_BASE_URL || (
  window.location.port === '8000' 
    ? window.location.origin 
    : 'http://127.0.0.1:8000'
);

export default function App() {
  const [activeTab, setActiveTab] = useState('single');
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [apiStatus, setApiStatus] = useState({ online: false, latency: null });
  const [showFeatures, setShowFeatures] = useState(false);

  // Check backend health on mount
  useEffect(() => {
    checkHealth();
  }, []);

  const checkHealth = async () => {
    const t0 = performance.now();
    try {
      const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
      const latency = Math.round(performance.now() - t0);
      if (res.ok) {
        const data = await res.json();
        if (data.status === 'healthy') {
          setApiStatus({ online: true, latency });
          return;
        }
      }
      throw new Error();
    } catch {
      setApiStatus({ online: false, latency: null });
    }
  };

  const handleScan = async (targetUrl) => {
    const urlToTest = (targetUrl || urlInput).trim();
    if (!urlToTest) return;

    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlToTest }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Server returned ${res.status}`);
      }

      const data = await res.json();
      setAnalysisResult(data);
    } catch (err) {
      console.error('Analysis error:', err);
      setAnalysisResult({
        url: urlToTest,
        verdict: 'INVALID',
        safety_score: null,
        risk_score_pct: null,
        confidence_pct: null,
        explanation: err.message || "Website doesn't exist - please enter a valid URL.",
        risk_indicators: [],
        features: null,
        latency_ms: 0,
      });
    } finally {
      setLoading(false);
    }
  };

  const triggerPreset = (presetUrl) => {
    setUrlInput(presetUrl);
    handleScan(presetUrl);
  };

  return (
    <div className="cyber-canvas min-h-screen flex flex-col antialiased">
      {/* Top Navbar */}
      <header className="border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          {/* Logo */}
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setActiveTab('single')}>
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <ShieldCheck className="w-6 h-6 text-white" />
            </div>
            <div>
              <span className="text-xl font-bold tracking-tight bg-gradient-to-r from-white via-slate-200 to-cyan-400 bg-clip-text text-transparent font-display">
                SafeWeb
              </span>
              <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 ml-2">
                React + Vite
              </span>
            </div>
          </div>

          {/* Navigation Pill Tabs */}
          <nav className="hidden md:flex items-center space-x-1 p-1 bg-slate-900/90 rounded-xl border border-slate-800">
            <button
              onClick={() => setActiveTab('single')}
              className={`px-4 py-1.5 rounded-lg text-sm font-semibold transition-all flex items-center space-x-2 ${
                activeTab === 'single'
                  ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Scan className="w-4 h-4" />
              <span>URL Scanner</span>
            </button>
            <button
              onClick={() => setActiveTab('batch')}
              className={`px-4 py-1.5 rounded-lg text-sm font-semibold transition-all flex items-center space-x-2 ${
                activeTab === 'batch'
                  ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Layers className="w-4 h-4" />
              <span>Batch Audit</span>
            </button>
            <button
              onClick={() => setActiveTab('model')}
              className={`px-4 py-1.5 rounded-lg text-sm font-semibold transition-all flex items-center space-x-2 ${
                activeTab === 'model'
                  ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Brain className="w-4 h-4" />
              <span>AI Architecture</span>
            </button>
          </nav>

          {/* API Health Pill & Docs */}
          <div className="flex items-center space-x-3">
            <div 
              onClick={checkHealth}
              title="Click to re-ping API"
              className="flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-semibold bg-slate-900 border border-slate-800 cursor-pointer hover:border-slate-700 transition"
            >
              <span className={`w-2 h-2 rounded-full ${apiStatus.online ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
              <span className={apiStatus.online ? 'text-slate-300' : 'text-rose-400'}>
                {apiStatus.online ? `API Online (${apiStatus.latency}ms)` : 'API Disconnected'}
              </span>
            </div>
            <a
              href={`${API_BASE}/docs`}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-slate-400 hover:text-cyan-400 p-2 rounded-lg hover:bg-slate-900 transition flex items-center space-x-1"
              title="Interactive Swagger Docs"
            >
              <FileCode className="w-4 h-4" />
              <span className="hidden sm:inline">API Docs</span>
            </a>
          </div>
        </div>
      </header>

      {/* Main Body */}
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-8">
        
        {/* ================================================================ */}
        {/* TAB 1: SINGLE SCANNER                                            */}
        {/* ================================================================ */}
        {activeTab === 'single' && (
          <div className="space-y-8">
            
            {/* Hero & Search Header */}
            <section className="text-center max-w-3xl mx-auto space-y-4 pt-4">
              <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-semibold">
                <Sparkles className="w-3.5 h-3.5" />
                <span>28 Lexical Features • XGBoost ML • Realistic Safety Scaling</span>
              </div>
              <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight font-display">
                Next-Gen AI <span className="bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-400 bg-clip-text text-transparent">Phishing Detector</span>
              </h1>
              <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
                Scan URLs in real-time. Detect deceptive lookalike domains, brand spoofing, and malicious token patterns before navigating.
              </p>

              {/* Main Scanner Search Bar */}
              <div className="pt-4 max-w-2xl mx-auto">
                <form
                  onSubmit={(e) => { e.preventDefault(); handleScan(); }}
                  className="relative flex items-center"
                >
                  <div className="absolute left-4 text-slate-500 pointer-events-none">
                    <Globe className="w-5 h-5" />
                  </div>
                  <input
                    type="text"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    placeholder="Enter URL to inspect (e.g. https://google.com or suspicious link)..."
                    required
                    className="w-full pl-12 pr-32 py-4 bg-slate-900/90 border border-slate-700/80 rounded-2xl text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/30 transition-all text-sm sm:text-base shadow-2xl font-mono"
                  />
                  <div className="absolute right-2 flex items-center space-x-1">
                    {urlInput && (
                      <button
                        type="button"
                        onClick={() => setUrlInput('')}
                        className="text-slate-500 hover:text-slate-300 p-2 rounded-lg"
                        title="Clear"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    )}
                    <button
                      type="submit"
                      disabled={loading || !urlInput.trim()}
                      className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold text-sm transition-all shadow-md shadow-cyan-500/25 flex items-center space-x-2 disabled:opacity-50"
                    >
                      {loading ? (
                        <>
                          <Loader2 className="w-4 h-4 animate-spin" />
                          <span>Scanning...</span>
                        </>
                      ) : (
                        <>
                          <Search className="w-4 h-4" />
                          <span>Analyze</span>
                        </>
                      )}
                    </button>
                  </div>
                </form>

                {/* Quick Presets */}
                <div className="flex flex-wrap items-center justify-center gap-2 pt-4 text-xs">
                  <span className="text-slate-500 font-medium">Try Presets:</span>
                  <button
                    type="button"
                    onClick={() => triggerPreset('https://google.com')}
                    className="px-2.5 py-1 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition flex items-center space-x-1.5"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                    <span>Google</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => triggerPreset('https://github.com/torvalds/linux')}
                    className="px-2.5 py-1 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition flex items-center space-x-1.5"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                    <span>GitHub Repo</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => triggerPreset('http://secure-paypal-login-verify.tk/signin')}
                    className="px-2.5 py-1 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/50 transition flex items-center space-x-1.5"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
                    <span>PayPal Phish Demo</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => triggerPreset('http://192.168.1.1:8080/paypal/login.php')}
                    className="px-2.5 py-1 rounded-lg bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 border border-rose-800/50 transition flex items-center space-x-1.5"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
                    <span>IP Attack Demo</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => triggerPreset('asdfghjkl random text')}
                    className="px-2.5 py-1 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-slate-200 border border-slate-700 transition flex items-center space-x-1.5"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-slate-400" />
                    <span>Random Text Demo</span>
                  </button>
                </div>
              </div>
            </section>

            {/* Analysis Results Display */}
            {analysisResult && (
              <section className="max-w-4xl mx-auto space-y-6 animate-in fade-in duration-500">
                
                {/* 1. Verdict Banner */}
                <VerdictBanner data={analysisResult} />

                {/* 2. 3-Card Grid with Circular Gauge */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  
                  {/* Card 1: Circular Safety Gauge */}
                  <div className="glass-panel rounded-2xl flex flex-col justify-center">
                    <ScoreGauge 
                      safetyScore={analysisResult.safety_score} 
                      verdict={analysisResult.verdict} 
                    />
                  </div>

                  {/* Card 2: Phishing Probability Bar */}
                  <div className="glass-panel rounded-2xl p-6 flex flex-col justify-between">
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-semibold text-slate-400 tracking-wider uppercase">
                          Phishing Probability
                        </span>
                        <span className={`text-xs px-2 py-0.5 rounded-full font-bold ${
                          analysisResult.risk_score_pct >= 60 
                            ? 'bg-rose-950 text-rose-300 border border-rose-800' 
                            : analysisResult.risk_score_pct >= 35 
                            ? 'bg-amber-950 text-amber-300 border border-amber-800' 
                            : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        }`}>
                          {analysisResult.risk_score_pct !== null ? `${analysisResult.risk_score_pct}% Risk` : 'N/A'}
                        </span>
                      </div>

                      {/* Progress Bar */}
                      <div className="w-full bg-slate-800 rounded-full h-3 overflow-hidden my-3">
                        <div
                          className={`h-3 rounded-full transition-all duration-1000 ${
                            analysisResult.risk_score_pct >= 60 
                              ? 'bg-rose-500' 
                              : analysisResult.risk_score_pct >= 35 
                              ? 'bg-amber-500' 
                              : 'bg-emerald-500'
                          }`}
                          style={{ width: `${Math.min(analysisResult.risk_score_pct || 0, 100)}%` }}
                        />
                      </div>

                      <div className="flex justify-between text-[11px] text-slate-500 font-mono">
                        <span>0% (Safe)</span>
                        <span>40% (Threshold)</span>
                        <span>100% (Phish)</span>
                      </div>
                    </div>

                    <div className="mt-4 pt-4 border-t border-slate-800/80 text-xs text-slate-400 space-y-1.5">
                      <div className="flex justify-between">
                        <span>Confidence Level:</span>
                        <span className="font-semibold text-slate-200 font-mono">
                          {analysisResult.confidence_pct ? `${analysisResult.confidence_pct}%` : 'N/A'}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span>Decision Classification:</span>
                        <span className="font-semibold text-slate-200">
                          {analysisResult.verdict}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Card 3: Domain Anatomy */}
                  <div className="glass-panel rounded-2xl p-6 flex flex-col justify-between">
                    <div>
                      <h3 className="text-xs font-semibold text-slate-400 tracking-wider uppercase mb-3">
                        Domain & Routing Anatomy
                      </h3>
                      
                      <div className="space-y-2.5 text-xs">
                        <div className="flex justify-between py-1 border-b border-slate-800/80">
                          <span className="text-slate-500">Registered Host:</span>
                          <span className="font-semibold text-slate-200 font-mono truncate max-w-[150px]">
                            {analysisResult.registered_domain || 'N/A'}
                          </span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-800/80">
                          <span className="text-slate-500">Canonical Path:</span>
                          <span className="font-semibold text-slate-200 font-mono truncate max-w-[150px]">
                            {analysisResult.normalized_url || 'N/A'}
                          </span>
                        </div>
                        <div className="flex justify-between py-1 border-b border-slate-800/80">
                          <span className="text-slate-500">Threat Signals:</span>
                          <span className="font-semibold text-slate-200">
                            {(analysisResult.risk_indicators || []).length} detected
                          </span>
                        </div>
                        <div className="flex justify-between py-1">
                          <span className="text-slate-500">Inference Latency:</span>
                          <span className="font-semibold text-cyan-400 font-mono">
                            {analysisResult.latency_ms || 0} ms
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="text-[11px] text-slate-500 pt-2 border-t border-slate-800/80">
                      Standardized with RFC 1035 syntax & public-suffix lists.
                    </div>
                  </div>

                </div>

                {/* 3. Security Assessment & Threat Indicators */}
                <div className="glass-panel rounded-2xl p-6 space-y-4">
                  <h3 className="text-base font-bold text-white font-display flex items-center space-x-2">
                    <Shield className="w-5 h-5 text-cyan-400" />
                    <span>Security Assessment & Threat Explanations</span>
                  </h3>

                  <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 text-sm text-slate-300 leading-relaxed font-sans">
                    {analysisResult.explanation || analysisResult.error}
                  </div>

                  {/* List of Threat Flags */}
                  <div className="space-y-2 pt-1">
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-2">
                      Specific Threat Signals
                    </span>

                    {analysisResult.risk_indicators && analysisResult.risk_indicators.length > 0 ? (
                      analysisResult.risk_indicators.map((ind, i) => (
                        <div
                          key={i}
                          className="p-3 rounded-xl bg-rose-950/20 border border-rose-900/40 text-xs text-rose-300 flex items-start space-x-2.5"
                        >
                          <AlertOctagon className="w-4 h-4 text-rose-400 flex-shrink-0 mt-0.5" />
                          <span>{ind}</span>
                        </div>
                      ))
                    ) : analysisResult.verdict === 'SAFE' ? (
                      <div className="p-3 rounded-xl bg-emerald-950/20 border border-emerald-900/40 text-xs text-emerald-300 flex items-center space-x-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                        <span>No deceptive brand impersonation or malicious patterns identified.</span>
                      </div>
                    ) : (
                      <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-400 flex items-center space-x-2">
                        <span>Target could not be analyzed due to invalid syntax or non-existent domain.</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* 4. Collapsible 28 Lexical Features Grid */}
                {analysisResult.features && (
                  <div className="glass-panel rounded-2xl p-6">
                    <button
                      type="button"
                      onClick={() => setShowFeatures(!showFeatures)}
                      className="w-full flex items-center justify-between text-left"
                    >
                      <div className="flex items-center space-x-3">
                        <Cpu className="w-5 h-5 text-cyan-400" />
                        <div>
                          <h4 className="text-base font-bold text-white font-display">
                            Extracted Lexical Features (28 Dimensions)
                          </h4>
                          <p className="text-xs text-slate-400">
                            Mathematical and structural properties supplied to the calibrated XGBoost model
                          </p>
                        </div>
                      </div>
                      <ChevronDown
                        className={`w-5 h-5 text-slate-400 transition-transform duration-300 ${
                          showFeatures ? 'rotate-180' : ''
                        }`}
                      />
                    </button>

                    {showFeatures && (
                      <div className="pt-6 mt-6 border-t border-slate-800 animate-in fade-in duration-300">
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                          {Object.entries(analysisResult.features).map(([key, val]) => (
                            <div
                              key={key}
                              className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col justify-between"
                            >
                              <span className="text-[11px] text-slate-400 truncate" title={key}>
                                {key}
                              </span>
                              <span className="text-sm font-bold text-slate-100 mt-1">
                                {typeof val === 'number' && !Number.isInteger(val) ? val.toFixed(3) : val}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

              </section>
            )}

          </div>
        )}

        {/* ================================================================ */}
        {/* TAB 2: BATCH URL AUDITING                                        */}
        {/* ================================================================ */}
        {activeTab === 'batch' && <BatchScanner apiBase={API_BASE} />}

        {/* ================================================================ */}
        {/* TAB 3: MODEL INTELLIGENCE                                        */}
        {/* ================================================================ */}
        {activeTab === 'model' && <ModelIntelligence />}

      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950/70 py-6 mt-16 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-400">SafeWeb AI Cybersecurity Platform • React + Vite Engine</span>
          </div>
          <div className="flex items-center space-x-4">
            <a href={`${API_BASE}/docs`} target="_blank" rel="noreferrer" className="hover:text-cyan-400 transition">
              OpenAPI Docs
            </a>
            <span>•</span>
            <a href={`${API_BASE}/api/model-info`} target="_blank" rel="noreferrer" className="hover:text-cyan-400 transition">
              Model JSON
            </a>
            <span>•</span>
            <a href={`${API_BASE}/health`} target="_blank" rel="noreferrer" className="hover:text-cyan-400 transition">
              Health Probe
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}

