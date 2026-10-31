import React, { useState } from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, HelpCircle, Copy, Check, ExternalLink } from 'lucide-react';

export default function VerdictBanner({ data }) {
  const [copied, setCopied] = useState(false);
  const verdict = data?.verdict || 'INVALID';

  const handleCopy = () => {
    if (!data?.url) return;
    navigator.clipboard.writeText(data.url).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  let config = {
    glowClass: 'status-glow-safe',
    badgeBg: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
    iconBg: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    title: 'Legitimate & Safe Website',
    badgeText: 'SAFE / LEGITIMATE',
    icon: ShieldCheck,
  };

  if (verdict === 'PHISHING') {
    config = {
      glowClass: 'status-glow-phishing',
      badgeBg: 'bg-rose-500/20 text-rose-400 border-rose-500/40 animate-pulse',
      iconBg: 'bg-rose-500/20 text-rose-400 border-rose-500/30',
      title: 'Phishing Threat Detected',
      badgeText: 'PHISHING / DANGEROUS',
      icon: ShieldAlert,
    };
  } else if (verdict === 'SUSPICIOUS') {
    config = {
      glowClass: 'status-glow-suspicious',
      badgeBg: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
      iconBg: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
      title: 'Caution Advised - Unverified Signals',
      badgeText: 'SUSPICIOUS / CAUTION',
      icon: AlertTriangle,
    };
  } else if (verdict === 'INVALID') {
    config = {
      glowClass: 'status-glow-invalid',
      badgeBg: 'bg-slate-800 text-slate-400 border-slate-700',
      iconBg: 'bg-slate-800 text-slate-400 border-slate-700',
      title: "Website Doesn't Exist",
      badgeText: 'INVALID INPUT',
      icon: HelpCircle,
    };
  }

  const IconComponent = config.icon;

  return (
    <div className={`glass-panel rounded-2xl p-6 border transition-all ${config.glowClass}`}>
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        {/* Left: Icon & Verdict */}
        <div className="flex items-start md:items-center space-x-4">
          <div className={`w-14 h-14 rounded-2xl flex items-center justify-center flex-shrink-0 shadow-lg border ${config.iconBg}`}>
            <IconComponent className="w-8 h-8" />
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <span className={`px-3 py-1 rounded-full text-xs font-extrabold tracking-wider uppercase border shadow-sm ${config.badgeBg}`}>
                {config.badgeText}
              </span>
              <span className="text-xs text-slate-400 font-mono bg-slate-900/80 px-2 py-0.5 rounded-md border border-slate-800">
                {data.latency_ms || 0} ms
              </span>
            </div>
            <h2 className="text-2xl font-bold mt-1 text-white font-display">
              {config.title}
            </h2>
            <p className="text-xs text-slate-400 font-mono truncate max-w-xl mt-0.5" title={data.url}>
              {data.url}
            </p>
          </div>
        </div>

        {/* Right: Actions */}
        <div className="flex items-center space-x-2 self-end md:self-center">
          <button
            onClick={handleCopy}
            className="px-3.5 py-2 rounded-xl bg-slate-800/80 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition flex items-center space-x-1.5 shadow-sm"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400">Copied!</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy URL</span>
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

