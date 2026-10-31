import React from 'react';
import { Cpu, ShieldCheck, Database, Layers, CheckCircle2 } from 'lucide-react';

export default function ModelIntelligence() {
  const topFeatures = [
    { name: 'tld_length', score: '0.1042', desc: 'Length of top-level domain suffix' },
    { name: 'num_hyphens', score: '0.1035', desc: 'Count of hyphens across the entire URL' },
    { name: 'path_length', score: '0.0513', desc: 'Character length of the path segment' },
    { name: 'digit_ratio', score: '0.0479', desc: 'Ratio of numeric digits to total length' },
    { name: 'num_dots', score: '0.0430', desc: 'Total period count in canonical URL' },
    { name: 'domain_entropy', score: '0.0401', desc: 'Shannon randomness in domain characters' },
  ];

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      <div>
        <h2 className="text-2xl font-bold text-white font-display">SafeWeb AI Architecture & Transparency</h2>
        <p className="text-sm text-slate-400">
          Trained on 297,803 real-world URLs with leak-free domain splits and isotonic probability calibration.
        </p>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="glass-panel rounded-2xl p-5 text-center">
          <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Test ROC-AUC</p>
          <p className="text-3xl font-extrabold text-cyan-400 mt-2 font-mono">0.8406</p>
          <p className="text-[11px] text-slate-500 mt-1">High discrimination power</p>
        </div>

        <div className="glass-panel rounded-2xl p-5 text-center">
          <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Brier Score</p>
          <p className="text-3xl font-extrabold text-emerald-400 mt-2 font-mono">0.1168</p>
          <p className="text-[11px] text-slate-500 mt-1">Calibrated probabilities</p>
        </div>

        <div className="glass-panel rounded-2xl p-5 text-center">
          <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Dataset Size</p>
          <p className="text-3xl font-extrabold text-indigo-400 mt-2 font-mono">297,803</p>
          <p className="text-[11px] text-slate-500 mt-1">Clean, balanced URLs</p>
        </div>

        <div className="glass-panel rounded-2xl p-5 text-center">
          <p className="text-xs text-slate-400 font-semibold uppercase tracking-wider">ML Estimator</p>
          <p className="text-2xl font-extrabold text-purple-400 mt-2">XGBoost</p>
          <p className="text-[11px] text-slate-500 mt-1">Isotonic calibrated</p>
        </div>
      </div>

      {/* 3-Layer Defense */}
      <div className="glass-panel rounded-2xl p-6 space-y-4">
        <h3 className="text-lg font-bold text-white font-display flex items-center space-x-2">
          <Layers className="w-5 h-5 text-cyan-400" />
          <span>The 3-Layer Defense Pipeline</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/20 text-cyan-400 flex items-center justify-center font-bold text-sm">
              1
            </div>
            <h4 className="font-bold text-white text-sm">Syntax & Domain Gate</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Catches keyboard mashing, plain text, and invalid TLDs. Ensures only real, syntactically valid web destinations proceed to inference.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/20 text-emerald-400 flex items-center justify-center font-bold text-sm">
              2
            </div>
            <h4 className="font-bold text-white text-sm">Reputation Whitelist</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Applies realistic safety ratings (92-96/100) to top trusted domains while recognizing no site is 100% immune to malicious user links or open redirects.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
            <div className="w-8 h-8 rounded-lg bg-rose-500/20 text-rose-400 flex items-center justify-center font-bold text-sm">
              3
            </div>
            <h4 className="font-bold text-white text-sm">XGBoost + Threat Rules</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Assesses 28 lexical features combined with real-world threat indicators (brand spoofing, high-risk TLDs like .tk, raw IP addresses, entropy).
            </p>
          </div>
        </div>
      </div>

      {/* Feature Importances */}
      <div className="glass-panel rounded-2xl p-6 space-y-3">
        <h3 className="text-base font-bold text-white font-display flex items-center space-x-2">
          <Cpu className="w-5 h-5 text-indigo-400" />
          <span>Top Predictive Features</span>
        </h3>
        <p className="text-xs text-slate-400">
          Features providing the greatest predictive signal for separating legitimate URLs from deceptive ones:
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
          {topFeatures.map((f, i) => (
            <div key={i} className="p-3 rounded-xl bg-slate-900/70 border border-slate-800 flex justify-between items-center">
              <div>
                <span className="text-xs font-mono font-semibold text-slate-200">{i + 1}. {f.name}</span>
                <p className="text-[10px] text-slate-500">{f.desc}</p>
              </div>
              <span className="text-sm font-mono font-bold text-cyan-400">{f.score}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

