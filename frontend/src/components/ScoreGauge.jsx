import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, HelpCircle } from 'lucide-react';

export default function ScoreGauge({ safetyScore, verdict }) {
  // Radius and circumference for SVG circle
  const radius = 54;
  const strokeWidth = 9;
  const circumference = 2 * Math.PI * radius; // ~339.29

  // Calculate stroke offset
  const validScore = typeof safetyScore === 'number' && !isNaN(safetyScore);
  const clampedScore = validScore ? Math.max(0, Math.min(100, safetyScore)) : 0;
  const strokeDashoffset = validScore 
    ? circumference - (clampedScore / 100) * circumference 
    : circumference;

  // Determine color theme based on verdict and score
  let theme = {
    gradientId: 'gaugeSafe',
    colorStart: '#10b981', // Emerald
    colorEnd: '#34d399',
    glowColor: 'rgba(16, 185, 129, 0.35)',
    textColor: 'text-emerald-400',
    bgColor: 'bg-emerald-500/10',
    borderColor: 'border-emerald-500/30',
    title: 'High Safety Rating',
    subtext: 'No deceptive patterns detected',
    icon: ShieldCheck,
  };

  if (verdict === 'PHISHING' || (validScore && clampedScore < 40)) {
    theme = {
      gradientId: 'gaugePhish',
      colorStart: '#ef4444', // Crimson Red
      colorEnd: '#f43f5e',
      glowColor: 'rgba(239, 68, 68, 0.45)',
      textColor: 'text-rose-400',
      bgColor: 'bg-rose-500/10',
      borderColor: 'border-rose-500/30',
      title: 'Critical Threat Level',
      subtext: 'Deceptive or phishing signals active',
      icon: ShieldAlert,
    };
  } else if (verdict === 'SUSPICIOUS' || (validScore && clampedScore < 80)) {
    theme = {
      gradientId: 'gaugeSuspicious',
      colorStart: '#f59e0b', // Electric Amber
      colorEnd: '#fbbf24',
      glowColor: 'rgba(245, 158, 11, 0.35)',
      textColor: 'text-amber-400',
      bgColor: 'bg-amber-500/10',
      borderColor: 'border-amber-500/30',
      title: 'Moderate Caution',
      subtext: 'Mixed signals; verify before trusting',
      icon: AlertTriangle,
    };
  } else if (verdict === 'INVALID' || !validScore) {
    theme = {
      gradientId: 'gaugeInvalid',
      colorStart: '#64748b', // Slate Gray
      colorEnd: '#94a3b8',
      glowColor: 'rgba(100, 116, 139, 0.2)',
      textColor: 'text-slate-400',
      bgColor: 'bg-slate-800/40',
      borderColor: 'border-slate-700/40',
      title: 'Non-Existent Target',
      subtext: "Domain doesn't exist on internet",
      icon: HelpCircle,
    };
  }

  const IconComponent = theme.icon;

  return (
    <div className="flex flex-col items-center justify-center p-6 text-center relative">
      {/* Background radial glow */}
      <div 
        className="absolute w-44 h-44 rounded-full blur-3xl pointer-events-none transition-all duration-700"
        style={{ background: theme.glowColor }}
      />

      {/* SVG Circular Radial Gauge */}
      <div className="relative w-44 h-44 flex items-center justify-center">
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 140 140">
          <defs>
            <linearGradient id={theme.gradientId} x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor={theme.colorStart} />
              <stop offset="100%" stopColor={theme.colorEnd} />
            </linearGradient>
          </defs>

          {/* Decorative outer dashed track */}
          <circle
            cx="70"
            cy="70"
            r="64"
            fill="none"
            stroke="rgba(255, 255, 255, 0.05)"
            strokeWidth="1.5"
            strokeDasharray="4 4"
          />

          {/* Background circle track */}
          <circle
            cx="70"
            cy="70"
            r={radius}
            fill="none"
            stroke="#141c2e"
            strokeWidth={strokeWidth}
          />

          {/* Active Progress Arc */}
          <circle
            cx="70"
            cy="70"
            r={radius}
            fill="none"
            stroke={`url(#${theme.gradientId})`}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            className="gauge-arc"
          />
        </svg>

        {/* Center Score Display */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className={`text-4xl font-extrabold font-mono tracking-tight ${theme.textColor}`}>
            {validScore ? clampedScore.toFixed(1) : '--'}
          </span>
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 mt-0.5">
            / 100 Safe
          </span>
        </div>
      </div>

      {/* Qualitative Label Badge */}
      <div className={`mt-4 px-3.5 py-1 rounded-full text-xs font-bold uppercase tracking-wider flex items-center space-x-1.5 ${theme.bgColor} ${theme.borderColor} ${theme.textColor} border shadow-sm`}>
        <IconComponent className="w-3.5 h-3.5" />
        <span>{theme.title}</span>
      </div>

      <p className="text-xs text-slate-400 mt-2 max-w-[210px] leading-relaxed">
        {theme.subtext}
      </p>
      
      {validScore && (
        <span className="text-[10px] text-slate-500 mt-1">
          Realistic scale (max 96.0; no site is 100% immune)
        </span>
      )}
    </div>
  );
}

