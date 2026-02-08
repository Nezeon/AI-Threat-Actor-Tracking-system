import React, { useState, useEffect } from 'react';
import { ThreatActor } from '../../types';
import { INITIAL_THREAT_ACTORS } from '../../constants';
import { Plus, Search, Shield, Download, AlertTriangle, Activity, Target, Trash2, RefreshCw, ExternalLink, Globe, Link as LinkIcon, CheckCircle, Search as SearchIcon, RotateCw } from 'lucide-react';
import { generateActorProfile, refreshActorSection } from '../../services/geminiService';
import * as XLSX from 'xlsx';

const ThreatActorPanel: React.FC = () => {
  // Initialize from localStorage or fallback to constants
  const [actors, setActors] = useState<ThreatActor[]>(() => {
    try {
      const saved = localStorage.getItem('hivepro_threat_actors');
      let loadedActors = saved ? JSON.parse(saved) : INITIAL_THREAT_ACTORS;
      
      // Robust sanitization/migration for existing local storage data
      if (Array.isArray(loadedActors)) {
          loadedActors = loadedActors.map((actor: any) => ({
              ...actor,
              sources: actor.sources || [], 
              cves: actor.cves || [],
              aliases: actor.aliases || []
          }));
      } else {
          loadedActors = INITIAL_THREAT_ACTORS;
      }
      
      return loadedActors;
    } catch (e) {
      console.error("Failed to load actors from local storage", e);
      return INITIAL_THREAT_ACTORS;
    }
  });

  const [selectedActorId, setSelectedActorId] = useState<string>(() => {
    return actors.length > 0 ? actors[0].id : '';
  });
  
  const [searchTerm, setSearchTerm] = useState('');
  const [isAdding, setIsAdding] = useState(false);
  const [newActorName, setNewActorName] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [refreshingSection, setRefreshingSection] = useState<string | null>(null);

  // Migration Effect
  useEffect(() => {
    setActors(prevActors => {
      let hasChanges = false;
      const updatedActors = prevActors.map(actor => {
        const defaultVer = INITIAL_THREAT_ACTORS.find(d => d.id === actor.id);
        if (defaultVer && defaultVer.cves.length > actor.cves.length) {
          hasChanges = true;
          return {
            ...defaultVer,
            lastUpdated: new Date().toISOString()
          };
        }
        return actor;
      });
      return hasChanges ? updatedActors : prevActors;
    });
  }, []);

  // Persist actors
  useEffect(() => {
    localStorage.setItem('hivepro_threat_actors', JSON.stringify(actors));
  }, [actors]);

  // Ensure selectedActorId is valid
  useEffect(() => {
    if (actors.length > 0 && !actors.find(a => a.id === selectedActorId)) {
      setSelectedActorId(actors[0].id);
    }
  }, [actors, selectedActorId]);

  const selectedActor = actors.find(a => a.id === selectedActorId) || actors[0];

  const handleAddActor = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newActorName.trim()) return;

    setIsLoading(true);
    try {
      const profile = await generateActorProfile(newActorName);
      const newActor: ThreatActor = {
        id: Date.now().toString(),
        lastUpdated: new Date().toISOString(),
        ...profile
      };
      setActors(prev => [...prev, newActor]);
      setSelectedActorId(newActor.id);
      setNewActorName('');
      setIsAdding(false);
    } catch (err) {
      alert("Failed to generate threat profile. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleRefreshActor = async () => {
    if (!selectedActor) return;

    setIsRefreshing(true);
    try {
      const profile = await generateActorProfile(selectedActor.name);
      
      const updatedActor: ThreatActor = {
        ...selectedActor,
        ...profile, 
        lastUpdated: new Date().toISOString()
      };

      setActors(prev => prev.map(a => a.id === selectedActor.id ? updatedActor : a));
    } catch (err) {
      console.error("Refresh failed", err);
      alert("Failed to refresh profile. Please check your connection.");
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleSectionRefresh = async (section: 'ALIASES' | 'DESCRIPTION' | 'CVES') => {
    if (!selectedActor) return;
    setRefreshingSection(section);
    
    try {
        const partialData = await refreshActorSection(selectedActor.name, section);
        setActors(prev => prev.map(a => {
            if (a.id !== selectedActor.id) return a;
            return { ...a, ...partialData, lastUpdated: new Date().toISOString() };
        }));
    } catch (err) {
        console.error("Section refresh failed", err);
    } finally {
        setRefreshingSection(null);
    }
  };

  const handleDeleteActor = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (confirm("Are you sure you want to remove this threat actor?")) {
      setActors(prev => prev.filter(a => a.id !== id));
    }
  };

  const exportReport = () => {
    if (!selectedActor) return;
    
    // Create workbook
    const wb = XLSX.utils.book_new();

    // --- Sheet 1: CVEs ---
    const cveData = selectedActor.cves.map(cve => ({
      "CVE ID": cve.id,
      "Severity": cve.severity,
      "Description": cve.description,
      "Verification Reference": cve.verificationReference || "N/A"
    }));
    const wsCVE = XLSX.utils.json_to_sheet(cveData);
    wsCVE['!cols'] = [{ wch: 20 }, { wch: 15 }, { wch: 80 }, { wch: 60 }];
    XLSX.utils.book_append_sheet(wb, wsCVE, "CVEs");

    // --- Sheet 2: Sources ---
    if (selectedActor.sources && selectedActor.sources.length > 0) {
      const sourceData = selectedActor.sources.map(s => ({
        "Title": s.title,
        "URL": s.url
      }));
      const wsSources = XLSX.utils.json_to_sheet(sourceData);
      wsSources['!cols'] = [{ wch: 50 }, { wch: 100 }];
      XLSX.utils.book_append_sheet(wb, wsSources, "Sources");
    }

    // Generate filename
    const cleanName = selectedActor.name.replace(/[^a-z0-9]/gi, '_').replace(/_+/g, '_');
    const fileName = `${cleanName}_Intel_Report.xlsx`;

    // Download logic
    const wbout = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
    const blob = new Blob([wbout], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
    const url = window.URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = fileName;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    window.URL.revokeObjectURL(url);
  };

  const filteredActors = actors.filter(a => 
    a.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
    a.aliases.some(alias => alias.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const getLinkDisplayInfo = (url: string) => {
    if (!url) return { text: 'Unverified', icon: AlertTriangle, isSearch: false };
    if (url.includes('google.com/search')) {
      return { text: 'Verify via Search', icon: SearchIcon, isSearch: true };
    }
    try {
      const domain = new URL(url).hostname.replace('www.', '');
      return { text: `View on ${domain}`, icon: CheckCircle, isSearch: false };
    } catch {
      return { text: 'View Report', icon: CheckCircle, isSearch: false };
    }
  };

  return (
    <div className="flex h-full w-full bg-slate-950 overflow-hidden">
      {/* Inner Sidebar for Threat Names */}
      <div className="w-80 bg-slate-900/50 border-r border-slate-800 flex flex-col flex-shrink-0">
        <div className="p-4 border-b border-slate-800">
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2 mb-4">
            <Shield className="w-5 h-5 text-yellow-500" />
            Threat Database
          </h2>
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
            <input 
              type="text" 
              placeholder="Search actors..." 
              className="w-full bg-slate-800 text-slate-200 text-sm rounded-lg pl-9 pr-3 py-2.5 focus:outline-none focus:ring-1 focus:ring-yellow-500/50"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {filteredActors.map(actor => (
            <div
              key={actor.id}
              onClick={() => setSelectedActorId(actor.id)}
              className={`w-full text-left p-3 rounded-lg text-sm transition-colors flex items-center justify-between group cursor-pointer
                ${selectedActorId === actor.id 
                  ? 'bg-slate-800 border-l-2 border-yellow-500 text-yellow-500' 
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
                }`}
            >
              <span className="font-medium truncate flex-1">{actor.name}</span>
              <div className="flex items-center gap-2">
                 {selectedActorId === actor.id && <div className="w-2 h-2 rounded-full bg-yellow-500 animate-pulse" />}
                 <button 
                   onClick={(e) => handleDeleteActor(actor.id, e)}
                   className="opacity-0 group-hover:opacity-100 p-1 hover:text-red-400 transition-opacity"
                   title="Delete"
                 >
                   <Trash2 className="w-3 h-3" />
                 </button>
              </div>
            </div>
          ))}
        </div>

        <div className="p-4 border-t border-slate-800">
          <button 
            onClick={() => setIsAdding(true)}
            className="w-full flex items-center justify-center gap-2 bg-yellow-600 hover:bg-yellow-500 text-slate-900 font-bold py-2.5 rounded-lg transition-colors text-sm"
          >
            <Plus className="w-4 h-4" /> Add New Threat Actor
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col h-full overflow-hidden relative">
        {selectedActor ? (
          <div className="flex-1 overflow-y-auto p-8">
            {/* Header */}
            <div className="flex justify-between items-start mb-8">
              <div className="flex-1">
                <h1 className="text-3xl font-bold text-white mb-3">{selectedActor.name}</h1>
                <div className="flex flex-wrap gap-2 text-sm items-center">
                  <span className="text-slate-400">AKA:</span>
                  {selectedActor.aliases.map(alias => (
                    <span key={alias} className="px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                      {alias}
                    </span>
                  ))}
                  <button 
                     onClick={() => handleSectionRefresh('ALIASES')}
                     disabled={!!refreshingSection}
                     className="ml-2 p-1 text-slate-500 hover:text-yellow-500 hover:bg-slate-800 rounded transition-colors disabled:opacity-30"
                     title="Refresh Aliases only"
                  >
                     <RotateCw className={`w-3.5 h-3.5 ${refreshingSection === 'ALIASES' ? 'animate-spin' : ''}`} />
                  </button>
                </div>
              </div>
              <div className="flex flex-col items-end gap-3">
                <div className="text-right">
                  <span className="text-xs text-slate-500 uppercase tracking-wider">Last Updated</span>
                  <p className="text-slate-300">{new Date(selectedActor.lastUpdated).toLocaleDateString()}</p>
                </div>
                <button 
                  onClick={handleRefreshActor}
                  disabled={isRefreshing || !!refreshingSection}
                  className="flex items-center gap-2 px-3 py-1.5 bg-yellow-900/20 hover:bg-yellow-900/40 text-yellow-500 rounded-lg text-xs font-semibold transition-all border border-yellow-900/50 disabled:opacity-50 disabled:cursor-wait"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
                  {isRefreshing ? 'Deep Scanning...' : 'Full Profile Refresh'}
                </button>
              </div>
            </div>

            {/* The 3 Paragraphs */}
            <div className="relative mb-10">
               <div className="absolute right-0 -top-8">
                   <button 
                     onClick={() => handleSectionRefresh('DESCRIPTION')}
                     disabled={!!refreshingSection}
                     className="flex items-center gap-1 text-xs text-slate-500 hover:text-yellow-500 transition-colors disabled:opacity-30"
                   >
                     <RotateCw className={`w-3 h-3 ${refreshingSection === 'DESCRIPTION' ? 'animate-spin' : ''}`} />
                     Refresh Intel Summary
                   </button>
               </div>
               
              <div className="grid gap-6">
                <div className="bg-slate-900/50 p-6 rounded-xl border border-slate-800 hover:border-slate-700 transition-colors">
                  <h3 className="text-yellow-500 font-semibold mb-3 flex items-center gap-2">
                    <Target className="w-4 h-4" />
                    Origin & First Observed
                  </h3>
                  <p className="text-slate-300 leading-relaxed text-sm">{selectedActor.description.summary}</p>
                </div>

                <div className="bg-slate-900/50 p-6 rounded-xl border border-slate-800 hover:border-slate-700 transition-colors">
                  <h3 className="text-yellow-500 font-semibold mb-3 flex items-center gap-2">
                    <Activity className="w-4 h-4" />
                    Campaigns & TTPs
                  </h3>
                  <p className="text-slate-300 leading-relaxed text-sm">{selectedActor.description.campaigns}</p>
                </div>

                <div className="bg-slate-900/50 p-6 rounded-xl border border-slate-800 hover:border-slate-700 transition-colors">
                  <h3 className="text-yellow-500 font-semibold mb-3 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" />
                    Recent Activity (Last 12 Months)
                  </h3>
                  <p className="text-slate-300 leading-relaxed text-sm">{selectedActor.description.recent}</p>
                </div>
              </div>
            </div>

            {/* CVE Section */}
            <div className="mb-8">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-xl font-bold text-white flex items-center gap-2">
                  Associated CVEs
                  <button 
                     onClick={() => handleSectionRefresh('CVES')}
                     disabled={!!refreshingSection}
                     className="p-1 text-slate-500 hover:text-yellow-500 rounded transition-colors disabled:opacity-30"
                     title="Refresh CVEs only"
                  >
                     <RotateCw className={`w-4 h-4 ${refreshingSection === 'CVES' ? 'animate-spin' : ''}`} />
                  </button>
                </h3>
                <button 
                  onClick={exportReport}
                  className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-sm transition-colors border border-slate-700"
                >
                  <Download className="w-4 h-4" /> Export Report (.xlsx)
                </button>
              </div>
              
              <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <table className="w-full text-left text-sm">
                  <thead className="bg-slate-800 text-slate-400 uppercase tracking-wider font-semibold">
                    <tr>
                      <th className="px-6 py-4">CVE ID</th>
                      <th className="px-6 py-4">Severity</th>
                      <th className="px-6 py-4">Description</th>
                      <th className="px-6 py-4">Verification</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {selectedActor.cves.length > 0 ? (
                      selectedActor.cves.map((cve) => {
                        const linkInfo = getLinkDisplayInfo(cve.verificationReference || '');
                        const LinkIconComponent = linkInfo.icon;
                        
                        return (
                        <tr key={cve.id} className="hover:bg-slate-800/30 transition-colors">
                          <td className="px-6 py-4 font-mono text-yellow-500">{cve.id}</td>
                          <td className="px-6 py-4">
                            <span className={`px-2 py-1 rounded text-xs font-bold
                              ${cve.severity === 'CRITICAL' ? 'bg-red-900/50 text-red-400 border border-red-900' : 
                                cve.severity === 'HIGH' ? 'bg-orange-900/50 text-orange-400 border border-orange-900' :
                                'bg-blue-900/50 text-blue-400 border border-blue-900'
                              }`}>
                              {cve.severity}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-slate-300">{cve.description}</td>
                          <td className="px-6 py-4">
                            {cve.verificationReference ? (
                              <a 
                                href={cve.verificationReference} 
                                target="_blank" 
                                rel="noopener noreferrer"
                                className={`flex items-center gap-2 hover:underline
                                  ${linkInfo.isSearch ? 'text-slate-400 hover:text-white' : 'text-yellow-500 hover:text-yellow-400'}
                                `}
                                title={cve.verificationReference}
                              >
                                <LinkIconComponent className="w-4 h-4" />
                                {linkInfo.text}
                              </a>
                            ) : (
                                <span className="text-slate-600 italic">Unverified</span>
                            )}
                          </td>
                        </tr>
                      )})
                    ) : (
                      <tr>
                        <td colSpan={4} className="px-6 py-8 text-center text-slate-500">
                          No confirmed and verified CVEs found for this actor.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

             {/* Sources Section */}
            {selectedActor.sources && selectedActor.sources.length > 0 && (
              <div className="mt-8 border-t border-slate-800 pt-6">
                <h3 className="text-lg font-bold text-white mb-4">Intelligence Sources</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {selectedActor.sources.map((source, idx) => (
                    <a 
                      key={idx} 
                      href={source.url} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="flex items-center gap-3 p-3 bg-slate-900/50 border border-slate-800 rounded-lg hover:border-yellow-600/50 hover:bg-slate-800 transition-all group"
                    >
                      <div className="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center flex-shrink-0 group-hover:bg-yellow-900/20">
                         <Globe className="w-4 h-4 text-slate-500 group-hover:text-yellow-500" />
                      </div>
                      <div className="overflow-hidden">
                        <p className="text-sm text-slate-300 truncate font-medium group-hover:text-yellow-500">{source.title}</p>
                        <p className="text-xs text-slate-500 truncate">{source.url}</p>
                      </div>
                      <ExternalLink className="w-4 h-4 text-slate-600 ml-auto group-hover:text-yellow-500" />
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="flex-1 flex items-center justify-center text-slate-500">
            <p>Select a threat actor to view details</p>
          </div>
        )}

        {/* Add Modal Overlay */}
        {isAdding && (
          <div className="absolute inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50">
            <div className="bg-slate-900 border border-slate-700 rounded-2xl p-8 w-[500px] shadow-2xl">
              <h2 className="text-2xl font-bold text-white mb-2">Identify New Threat</h2>
              <p className="text-slate-400 text-sm mb-6">Enter the name of the threat actor (e.g., "Fancy Bear", "Lapsus$"). AI will perform a deep web scan to generate the profile.</p>
              
              <form onSubmit={handleAddActor}>
                <input
                  type="text"
                  placeholder="Threat Actor Name"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl p-4 text-white focus:ring-2 focus:ring-yellow-500 focus:outline-none mb-6"
                  value={newActorName}
                  onChange={(e) => setNewActorName(e.target.value)}
                  autoFocus
                />
                
                <div className="flex gap-3 justify-end">
                  <button 
                    type="button" 
                    onClick={() => setIsAdding(false)}
                    className="px-5 py-2.5 text-slate-400 hover:text-white transition-colors"
                  >
                    Cancel
                  </button>
                  <button 
                    type="submit" 
                    disabled={isLoading}
                    className="px-6 py-2.5 bg-yellow-600 hover:bg-yellow-500 text-slate-900 font-bold rounded-xl flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {isLoading ? 'Deep Scanning...' : 'Generate Profile'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatActorPanel;