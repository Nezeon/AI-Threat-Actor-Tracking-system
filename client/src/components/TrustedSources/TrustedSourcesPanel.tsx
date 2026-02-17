import React, { useState, useEffect } from 'react';
import { Plus, Trash2, Globe, ShieldCheck, Search, Save, FileText, Upload, AlertCircle } from 'lucide-react';
import { getTrustedSources, getTrustedActorNames, addTrustedUrl, removeTrustedUrl, uploadTrustedFile, removeTrustedFile, TrustedSourcesResponse } from '../../services/apiService';

const TrustedSourcesPanel: React.FC = () => {
  const [selectedActor, setSelectedActor] = useState<string>('');
  const [newUrl, setNewUrl] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState<'urls' | 'files'>('urls');
  const [isProcessingFile, setIsProcessingFile] = useState(false);

  // Data from server
  const [urls, setUrls] = useState<{ id: number; url: string; actor_name: string }[]>([]);
  const [files, setFiles] = useState<{ id: number; file_name: string; file_type: string; content_length: number; created_at: string }[]>([]);
  const [allActors, setAllActors] = useState<string[]>([]);

  // Track all known actors (fetched from server)
  const [knownActors, setKnownActors] = useState<string[]>([]);

  // Fetch actor names that have trusted sources on mount
  useEffect(() => {
    getTrustedActorNames()
      .then(names => setKnownActors(names))
      .catch(err => console.warn("Could not fetch trusted actor names:", err.message));
  }, []);

  // Fetch sources when actor is selected
  useEffect(() => {
    if (!selectedActor.trim()) {
      setUrls([]);
      setFiles([]);
      return;
    }

    getTrustedSources(selectedActor.trim().toLowerCase())
      .then((data: TrustedSourcesResponse) => {
        setUrls(data.urls || []);
        setFiles(data.files || []);
      })
      .catch((err) => {
        console.warn("Could not fetch sources:", err.message);
        setUrls([]);
        setFiles([]);
      });
  }, [selectedActor]);

  // Update actor list when data changes
  useEffect(() => {
    const actorSet = new Set([...knownActors]);
    if (selectedActor.trim()) actorSet.add(selectedActor.trim().toLowerCase());
    const sorted = Array.from(actorSet).sort();
    if (JSON.stringify(sorted) !== JSON.stringify(allActors)) {
      setAllActors(sorted);
    }
  }, [knownActors, selectedActor]);

  const handleAddUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedActor.trim() || !newUrl.trim()) return;

    try {
      new URL(newUrl);
      const normalizedActor = selectedActor.trim().toLowerCase();

      const result = await addTrustedUrl(normalizedActor, newUrl.trim());
      setUrls(prev => [...prev, { id: result.id, url: newUrl.trim(), actor_name: normalizedActor }]);
      setKnownActors(prev => Array.from(new Set([...prev, normalizedActor])));
      setNewUrl('');
    } catch (err: any) {
      if (err.message?.includes('HTTP')) {
        alert("Failed to save URL. Please try again.");
      } else {
        alert("Please enter a valid URL (e.g., https://example.com)");
      }
    }
  };

  const handleRemoveUrl = async (id: number) => {
    try {
      await removeTrustedUrl(id);
      setUrls(prev => prev.filter(u => u.id !== id));
    } catch (err) {
      console.error("Failed to remove URL:", err);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !selectedActor.trim()) return;

    setIsProcessingFile(true);
    try {
      const normalizedActor = selectedActor.trim().toLowerCase();
      const result = await uploadTrustedFile(normalizedActor, file);
      setFiles(prev => [...prev, { id: result.id, file_name: result.file_name, file_type: file.name.endsWith('.pdf') ? 'pdf' : 'csv', content_length: 0, created_at: new Date().toISOString() }]);
      setKnownActors(prev => Array.from(new Set([...prev, normalizedActor])));
    } catch (error) {
      console.error(error);
      alert("Error uploading file. Please ensure it is a valid PDF or CSV.");
    } finally {
      setIsProcessingFile(false);
      e.target.value = '';
    }
  };

  const handleRemoveFile = async (id: number) => {
    try {
      await removeTrustedFile(id);
      setFiles(prev => prev.filter(f => f.id !== id));
    } catch (err) {
      console.error("Failed to remove file:", err);
    }
  };

  const filteredActors = searchTerm
    ? allActors.filter(a => a.toLowerCase().includes(searchTerm.toLowerCase()))
    : allActors;

  return (
    <div className="flex h-full w-full bg-slate-950 overflow-hidden">
      {/* Sidebar List */}
      <div className="w-80 bg-slate-900/50 border-r border-slate-800 flex flex-col flex-shrink-0">
        <div className="p-6 border-b border-slate-800">
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2 mb-2">
            <ShieldCheck className="w-5 h-5 text-green-500" />
            Approved Sources
          </h2>
          <p className="text-xs text-slate-400 mb-4">
            AI will validate against these sources.
          </p>
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
            <input
              type="text"
              placeholder="Filter actors..."
              className="w-full bg-slate-800 text-slate-200 text-sm rounded-lg pl-9 pr-3 py-2.5 focus:outline-none focus:ring-1 focus:ring-green-500/50"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-2">
          {filteredActors.length === 0 && (
            <div className="text-center p-4 text-slate-500 text-sm italic">
              No custom sources configured.
            </div>
          )}
          {filteredActors.map(actor => (
            <button
              key={actor}
              onClick={() => setSelectedActor(actor)}
              className={`w-full text-left p-3 rounded-lg text-sm transition-colors mb-1 capitalize flex justify-between items-center
                ${selectedActor === actor
                  ? 'bg-slate-800 border-l-2 border-green-500 text-green-500'
                  : 'text-slate-400 hover:bg-slate-800/50 hover:text-slate-200'
                }`}
            >
              <span>{actor}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 p-8 flex flex-col h-full overflow-hidden">
        <div className="max-w-3xl mx-auto w-full flex flex-col h-full">
          <h1 className="text-2xl font-bold text-white mb-6">Source Management</h1>

          <div className="flex gap-4 mb-6 border-b border-slate-800">
            <button
              onClick={() => setActiveTab('urls')}
              className={`pb-3 px-1 text-sm font-medium transition-colors border-b-2 ${activeTab === 'urls' ? 'border-green-500 text-green-500' : 'border-transparent text-slate-400 hover:text-slate-200'}`}
            >
              Platform URLs
            </button>
            <button
              onClick={() => setActiveTab('files')}
              className={`pb-3 px-1 text-sm font-medium transition-colors border-b-2 ${activeTab === 'files' ? 'border-green-500 text-green-500' : 'border-transparent text-slate-400 hover:text-slate-200'}`}
            >
              Trusted Files (PDF/CSV)
            </button>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 mb-8 shadow-xl">
            {activeTab === 'urls' ? (
              <>
                 <h3 className="text-md font-semibold text-slate-200 mb-4 flex items-center gap-2">
                  <Plus className="w-4 h-4 text-green-500" />
                  Add Approved URL
                </h3>
                <form onSubmit={handleAddUrl} className="space-y-4">
                  <div>
                    <label className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Threat Actor Name</label>
                    <input
                      type="text"
                      placeholder="e.g., APT29"
                      className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-white focus:border-green-500 focus:outline-none"
                      value={selectedActor}
                      onChange={(e) => setSelectedActor(e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Approved URL</label>
                    <div className="flex gap-2">
                      <input
                        type="url"
                        placeholder="https://vendor-report.com/analysis..."
                        className="flex-1 bg-slate-950 border border-slate-700 rounded-lg p-3 text-white focus:border-green-500 focus:outline-none"
                        value={newUrl}
                        onChange={(e) => setNewUrl(e.target.value)}
                      />
                      <button type="submit" className="bg-green-600 hover:bg-green-500 text-white px-6 rounded-lg font-bold transition-colors flex items-center gap-2">
                        <Save className="w-4 h-4" /> Save
                      </button>
                    </div>
                  </div>
                </form>
              </>
            ) : (
              <>
                <h3 className="text-md font-semibold text-slate-200 mb-4 flex items-center gap-2">
                  <Upload className="w-4 h-4 text-green-500" />
                  Upload Validation File
                </h3>
                <div className="space-y-4">
                  <div>
                    <label className="block text-xs text-slate-500 uppercase tracking-wider mb-1">Threat Actor Name</label>
                    <input
                      type="text"
                      placeholder="e.g., APT29"
                      className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-white focus:border-green-500 focus:outline-none"
                      value={selectedActor}
                      onChange={(e) => setSelectedActor(e.target.value)}
                    />
                  </div>

                  <div className="border-2 border-dashed border-slate-700 rounded-lg p-8 text-center hover:border-green-500 transition-colors bg-slate-950/50">
                     <input
                        type="file"
                        id="fileUpload"
                        accept=".pdf,.csv,.xlsx"
                        className="hidden"
                        onChange={handleFileUpload}
                        disabled={isProcessingFile || !selectedActor}
                     />
                     <label htmlFor="fileUpload" className={`cursor-pointer flex flex-col items-center ${!selectedActor ? 'opacity-50 pointer-events-none' : ''}`}>
                        {isProcessingFile ? (
                           <div className="w-8 h-8 border-2 border-green-500 border-t-transparent rounded-full animate-spin mb-2" />
                        ) : (
                           <FileText className="w-8 h-8 text-slate-500 mb-2" />
                        )}
                        <span className="text-slate-300 font-medium">Click to upload PDF or CSV</span>
                        <span className="text-xs text-slate-500 mt-1">Files are parsed on the server and used for strict validation</span>
                     </label>
                  </div>
                  {!selectedActor && (
                     <p className="text-xs text-yellow-500 flex items-center gap-1">
                        <AlertCircle className="w-3 h-3" /> Please enter a threat actor name first
                     </p>
                  )}
                </div>
              </>
            )}
          </div>

          {/* List Section */}
          <div className="flex-1 overflow-hidden flex flex-col">
            <h3 className="text-md font-semibold text-slate-200 mb-4 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-slate-400" />
              Active Sources
              {selectedActor && <span className="text-green-500 capitalize">for {selectedActor}</span>}
            </h3>

            <div className="flex-1 overflow-y-auto space-y-3 pr-2">
               {/* Display URLs */}
               {activeTab === 'urls' && urls.map((item) => (
                <div key={`url-${item.id}`} className="flex items-center justify-between p-4 bg-slate-900/50 border border-slate-800 rounded-lg group hover:border-slate-700">
                  <div className="flex items-center gap-3 overflow-hidden">
                    <Globe className="w-4 h-4 text-slate-500 flex-shrink-0" />
                    <a href={item.url} target="_blank" rel="noopener noreferrer" className="text-slate-300 text-sm truncate hover:text-green-400">
                      {item.url}
                    </a>
                  </div>
                  <button onClick={() => handleRemoveUrl(item.id)} className="p-2 text-slate-600 hover:text-red-400 opacity-0 group-hover:opacity-100">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}

              {/* Display Files */}
              {activeTab === 'files' && files.map((file) => (
                <div key={`file-${file.id}`} className="flex items-center justify-between p-4 bg-slate-900/50 border border-slate-800 rounded-lg group hover:border-slate-700">
                  <div className="flex items-center gap-3 overflow-hidden">
                    <FileText className="w-4 h-4 text-blue-500 flex-shrink-0" />
                    <div className="flex flex-col">
                       <span className="text-slate-300 text-sm truncate">{file.file_name}</span>
                       <span className="text-[10px] text-slate-500">{file.file_type.toUpperCase()} • {new Date(file.created_at).toLocaleDateString()}</span>
                    </div>
                  </div>
                  <button onClick={() => handleRemoveFile(file.id)} className="p-2 text-slate-600 hover:text-red-400 opacity-0 group-hover:opacity-100">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}

              {selectedActor &&
               ((activeTab === 'urls' && urls.length === 0) ||
                (activeTab === 'files' && files.length === 0)) && (
                <div className="p-4 border border-dashed border-slate-800 rounded-lg text-slate-500 text-center text-sm">
                  No {activeTab} configured for this actor.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default TrustedSourcesPanel;
