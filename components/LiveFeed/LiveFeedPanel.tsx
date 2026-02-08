import React, { useEffect, useState } from 'react';
import { NewsItem } from '../../types';
import { getLiveCyberNews } from '../../services/geminiService';
import { Globe, ExternalLink, RefreshCw, Clock } from 'lucide-react';

const LiveFeedPanel: React.FC = () => {
  const [news, setNews] = useState<NewsItem[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchNews = async () => {
    setLoading(true);
    const items = await getLiveCyberNews();
    setNews(items);
    setLoading(false);
  };

  useEffect(() => {
    fetchNews();
  }, []);

  return (
    <div className="h-full w-full bg-slate-950 p-8 overflow-y-auto">
      <div className="max-w-6xl mx-auto">
        <div className="flex justify-between items-center mb-10">
          <div>
            <h1 className="text-3xl font-bold text-white flex items-center gap-3">
              <Globe className="w-8 h-8 text-yellow-500" />
              Global Threat Stream
            </h1>
            <p className="text-slate-400 mt-2">Real-time intelligence aggregation from open sources.</p>
          </div>
          
          <button 
            onClick={fetchNews}
            disabled={loading}
            className="flex items-center gap-2 px-5 py-2.5 bg-slate-800 text-slate-200 rounded-lg hover:bg-slate-700 transition-colors border border-slate-700 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh Intel
          </button>
        </div>

        {loading && news.length === 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[1, 2, 3, 4, 5, 6].map((i) => (
              <div key={i} className="h-64 bg-slate-900/50 rounded-2xl animate-pulse border border-slate-800"></div>
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {news.map((item, idx) => (
              <div 
                key={idx} 
                className="bg-slate-900 border border-slate-800 rounded-2xl p-6 hover:border-yellow-500/50 transition-all duration-300 group flex flex-col"
              >
                <div className="flex justify-between items-start mb-4">
                  <span className="text-xs font-mono text-yellow-500 border border-yellow-900/50 bg-yellow-900/20 px-2 py-1 rounded">
                    {item.source}
                  </span>
                  <span className="text-xs text-slate-500 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {item.date || 'Today'}
                  </span>
                </div>
                
                <h3 className="text-lg font-bold text-slate-100 mb-3 leading-snug group-hover:text-yellow-400 transition-colors">
                  {item.title}
                </h3>
                
                <p className="text-slate-400 text-sm leading-relaxed mb-6 flex-1">
                  {item.summary}
                </p>
                
                <a 
                  href={item.url} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-sm font-medium text-slate-300 hover:text-white mt-auto pt-4 border-t border-slate-800"
                >
                  Read Source <ExternalLink className="w-4 h-4" />
                </a>
              </div>
            ))}
            
            {news.length === 0 && !loading && (
              <div className="col-span-full text-center py-20">
                <p className="text-slate-500 text-lg">Unable to fetch live intelligence at this moment.</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default LiveFeedPanel;