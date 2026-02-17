import React from 'react';
import { GenerationLog } from '../../types';
import { ChevronDown, ChevronRight, CheckCircle, ExternalLink, Globe, Clock, ShieldCheck, FileText } from 'lucide-react';

interface GenerationLogPanelProps {
  log: GenerationLog;
  isOpen: boolean;
  onToggle: () => void;
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

const GenerationLogPanel: React.FC<GenerationLogPanelProps> = ({ log, isOpen, onToggle }) => {
  const totalSources = log.groundingUrls.length + log.approvedSources.length + log.trustedFiles.length;

  return (
    <div className="mt-8 border border-slate-800 rounded-xl overflow-hidden bg-slate-900/30">
      {/* Toggle Header */}
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 px-5 py-3 hover:bg-slate-800/50 transition-colors text-left"
      >
        {isOpen ? (
          <ChevronDown className="w-4 h-4 text-yellow-500 flex-shrink-0" />
        ) : (
          <ChevronRight className="w-4 h-4 text-slate-400 flex-shrink-0" />
        )}
        <span className="text-sm font-semibold text-slate-300">Generation Log</span>
        <div className="flex items-center gap-3 ml-auto text-xs text-slate-500">
          <span className="flex items-center gap-1">
            <Clock className="w-3 h-3" />
            {formatDuration(log.totalDurationMs)}
          </span>
          <span>{log.steps.length} steps</span>
          <span>{totalSources} sources</span>
        </div>
      </button>

      {/* Expanded Content */}
      {isOpen && (
        <div className="border-t border-slate-800 px-5 py-4 space-y-5">
          {/* Section 1: Web Sources (AI Research) */}
          {log.groundingUrls.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Globe className="w-3.5 h-3.5" />
                Web Sources (AI Research)
              </h4>
              <div className="grid grid-cols-1 gap-1.5">
                {log.groundingUrls.map((source, idx) => (
                  <a
                    key={idx}
                    href={source.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-900/50 hover:bg-slate-800 border border-slate-800/50 hover:border-yellow-600/30 transition-all group text-sm"
                  >
                    <span className="text-slate-400 group-hover:text-yellow-500 truncate flex-1">
                      {source.title || source.url}
                    </span>
                    <ExternalLink className="w-3.5 h-3.5 text-slate-600 group-hover:text-yellow-500 flex-shrink-0" />
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Section 2: Approved & Reference Sources */}
          {log.approvedSources.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <ShieldCheck className="w-3.5 h-3.5" />
                Approved & Reference Sources
              </h4>
              <div className="grid grid-cols-1 gap-1.5">
                {log.approvedSources.map((source, idx) => (
                  <a
                    key={idx}
                    href={source.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-900/50 hover:bg-slate-800 border border-slate-800/50 hover:border-green-600/30 transition-all group text-sm"
                  >
                    <span className="text-slate-400 group-hover:text-green-500 truncate flex-1">
                      {source.title || source.url}
                    </span>
                    <ExternalLink className="w-3.5 h-3.5 text-slate-600 group-hover:text-green-500 flex-shrink-0" />
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Section 3: Trusted Files Used */}
          {log.trustedFiles.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <FileText className="w-3.5 h-3.5" />
                Trusted Files Used
              </h4>
              <div className="grid grid-cols-1 gap-1.5">
                {log.trustedFiles.map((fileName, idx) => (
                  <div
                    key={idx}
                    className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-900/50 border border-slate-800/50 text-sm"
                  >
                    <FileText className="w-3.5 h-3.5 text-blue-500 flex-shrink-0" />
                    <span className="text-slate-400 truncate flex-1">{fileName}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Section 4: Pipeline Steps */}
          <div>
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
              <CheckCircle className="w-3.5 h-3.5" />
              Pipeline Steps
            </h4>
            <div className="space-y-1">
              {log.steps.map((entry, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-3 px-3 py-2 rounded-lg bg-slate-900/50 border border-slate-800/50"
                >
                  <CheckCircle className="w-4 h-4 text-emerald-500 flex-shrink-0 mt-0.5" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-slate-300">{entry.label}</span>
                      {entry.durationMs != null && (
                        <span className="text-xs text-slate-600">{formatDuration(entry.durationMs)}</span>
                      )}
                    </div>
                    <p className="text-xs text-slate-500 mt-0.5">{entry.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default GenerationLogPanel;
