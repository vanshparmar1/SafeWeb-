import React, { useState } from 'react';
import { Play, Download, Trash2, FileText, CheckCircle2, AlertOctagon, HelpCircle } from 'lucide-react';

export default function BatchScanner({ apiBase }) {
  const [inputText, setInputText] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);

  const sampleUrls = [
    'https://google.com',
    'https://github.com/torvalds/linux',
    'http://secure-paypal-login-verify.tk/signin',
    'http://192.168.1.1:8080/paypal/login.php',
    'https://blog.python.org/2026/update',
    'asdfghjkl random text',
  ].join('\n');

  const handleAudit = async () => {
    const urls = inputText
      .split('\n')
      .map(u => u.trim())
      .filter(u => u.length > 0);

    if (urls.length === 0) return;

    setLoading(true);
    try {
      const res = await fetch(`${apiBase}/api/batch-analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ urls }),
      });

      if (!res.ok) throw new Error(`HTTP Error ${res.status}`);
      const data = await res.json();
      setResults(data);
    } catch (err) {
      console.error('Batch scan error:', err);
      alert(`Batch audit error: ${err.message}. Ensure backend is running.`);
    } finally {
      setLoading(false);
    }
  };

  const exportCSV = () => {
    if (!results || results.length === 0) return;
    const headers = ['URL', 'Verdict', 'Safety Score', 'Phishing Risk %', 'Registered Domain', 'Latency ms', 'Threat Indicators'];
    const rows = results.map(r => [
      `"${(r.url || '').replace(/"/g, '""')}"`,
      r.verdict,
      r.safety_score !== null ? r.safety_score : '',
      r.risk_score_pct !== null ? r.risk_score_pct : '',
      r.registered_domain || '',
      r.latency_ms || '',
      `"${(r.risk_indicators || []).join('; ').replace(/"/g, '""')}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const link = document.createElement('a');
    link.href = encodeURI(csvContent);
    link.download = `safeweb_bulk_audit_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      <div>
        <h2 className="text-2xl font-bold text-white font-display">Bulk URL Threat Audit</h2>
        <p className="text-sm text-slate-400">
          Analyze multiple links simultaneously with unified XGBoost classification & threat scoring.
        </p>
      </div>

      <div className="glass-panel rounded-2xl p-6 space-y-4">
        <textarea
          rows={6}
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          placeholder={`Paste URLs here, one per line:\nhttps://example.com\nhttp://phishing-site.tk/login`}
          className="w-full p-4 bg-slate-900/90 border border-slate-700/80 rounded-xl text-white placeholder-slate-500 font-mono text-sm focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30"
        />

        <div className="flex flex-wrap items-center justify-between gap-4">
          <button
            type="button"
            onClick={() => setInputText(sampleUrls)}
            className="text-xs text-slate-400 hover:text-cyan-400 transition underline underline-offset-4 flex items-center space-x-1"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Load Sample URLs</span>
          </button>

          <div className="flex items-center space-x-3">
            <button
              type="button"
              onClick={() => { setInputText(''); setResults([]); }}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-semibold transition flex items-center space-x-1.5"
            >
              <Trash2 className="w-4 h-4" />
              <span>Clear</span>
            </button>
            <button
              type="button"
              disabled={loading || !inputText.trim()}
              onClick={handleAudit}
              className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold text-sm transition shadow-lg shadow-cyan-500/20 disabled:opacity-50 flex items-center space-x-2"
            >
              <Play className="w-4 h-4 fill-white" />
              <span>{loading ? 'Auditing URLs...' : 'Run Bulk Audit'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Results Table */}
      {results.length > 0 && (
        <div className="glass-panel rounded-2xl p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-bold text-white font-display">
              Audit Results ({results.length} URLs)
            </h3>
            <button
              onClick={exportCSV}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition flex items-center space-x-1.5 shadow-sm"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export CSV</span>
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900/90 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">URL</th>
                  <th className="py-3 px-4">Verdict</th>
                  <th className="py-3 px-4">Safety Score</th>
                  <th className="py-3 px-4">Phishing Risk</th>
                  <th className="py-3 px-4">Threat Flags</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {results.map((r, i) => {
                  let badge = (
                    <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-slate-800 text-slate-400 border border-slate-700">
                      INVALID
                    </span>
                  );
                  if (r.verdict === 'SAFE') {
                    badge = (
                      <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                        SAFE
                      </span>
                    );
                  } else if (r.verdict === 'SUSPICIOUS') {
                    badge = (
                      <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">
                        SUSPICIOUS
                      </span>
                    );
                  } else if (r.verdict === 'PHISHING') {
                    badge = (
                      <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                        PHISHING
                      </span>
                    );
                  }

                  const safeDisplay = r.safety_score !== null 
                    ? <span className="font-bold text-white">{r.safety_score} <span className="text-slate-500">/ 100</span></span>
                    : <span className="text-slate-500">--</span>;

                  const riskDisplay = r.risk_score_pct !== null
                    ? `${r.risk_score_pct}%`
                    : '--';

                  const flagsCount = (r.risk_indicators || []).length;

                  return (
                    <tr key={i} className="hover:bg-slate-900/40 transition">
                      <td className="py-3 px-4 max-w-xs truncate" title={r.url}>{r.url}</td>
                      <td className="py-3 px-4">{badge}</td>
                      <td className="py-3 px-4">{safeDisplay}</td>
                      <td className="py-3 px-4">{riskDisplay}</td>
                      <td className="py-3 px-4">
                        {flagsCount > 0 ? (
                          <span className="text-rose-400 font-semibold">{flagsCount} detected</span>
                        ) : (
                          <span className="text-slate-500">0</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

