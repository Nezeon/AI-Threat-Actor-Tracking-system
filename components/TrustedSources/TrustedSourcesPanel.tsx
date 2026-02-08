import React, { useState, useEffect } from 'react';
import { Plus, Trash2, Globe, ShieldCheck, Search, Link as LinkIcon, Save, FileText, Upload, AlertCircle } from 'lucide-react';
import * as XLSX from 'xlsx';
import * as pdfjsLib from 'pdfjs-dist';

// Initialize PDF.js worker safely handling ESM default exports
const initPdfWorker = () => {
  const workerSrc = `https://esm.sh/pdfjs-dist@3.11.174/build/pdf.worker.min.js`;
  try {
    // Check if GlobalWorkerOptions is on the namespace or the default export
    if (pdfjsLib.GlobalWorkerOptions) {
      pdfjsLib.GlobalWorkerOptions.workerSrc = workerSrc;
    } else if ((pdfjsLib as any).default?.GlobalWorkerOptions) {
      (pdfjsLib as any).default.GlobalWorkerOptions.workerSrc = workerSrc;
    }
  } catch (e) {
    console.warn("Failed to initialize PDF Worker:", e);
  }
};

// Call initialization
initPdfWorker();

interface TrustedFile {
  name: string;
  type: 'pdf' | 'csv';
  content: string; // Extracted text content
  timestamp: number;
}

const TrustedSourcesPanel: React.FC = () => {
  // Store URLs: Record<ActorName, URL[]>
  const [trustedSources, setTrustedSources] = useState<Record<string, string[]>>(() => {
    try {
      const saved = localStorage.getItem('hivepro_trusted_sources');
      return saved ? JSON.parse(saved) : {};
    } catch (e) {
      return {};
    }
  });

  // Store Files: Record<ActorName, TrustedFile[]>
  const [trustedFiles, setTrustedFiles] = useState<Record<string, TrustedFile[]>>(() => {
    try {
      const saved = localStorage.getItem('hivepro_trusted_files');
      return saved ? JSON.parse(saved) : {};
    } catch (e) {
      return {};
    }
  });

  const [selectedActor, setSelectedActor] = useState<string>('');
  const [newUrl, setNewUrl] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [activeTab, setActiveTab] = useState<'urls' | 'files'>('urls');
  const [isProcessingFile, setIsProcessingFile] = useState(false);

  // Persist to localStorage
  useEffect(() => {
    localStorage.setItem('hivepro_trusted_sources', JSON.stringify(trustedSources));
  }, [trustedSources]);

  useEffect(() => {
    localStorage.setItem('hivepro_trusted_files', JSON.stringify(trustedFiles));
  }, [trustedFiles]);

  const handleAddUrl = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedActor.trim() || !newUrl.trim()) return;

    try {
      new URL(newUrl); // Validate format
      const normalizedActor = selectedActor.trim().toLowerCase();
      
      setTrustedSources(prev => {
        const currentUrls = prev[normalizedActor] || [];
        if (currentUrls.includes(newUrl.trim())) return prev;
        return {
          ...prev,
          [normalizedActor]: [...currentUrls, newUrl.trim()]
        };
      });
      setNewUrl('');
    } catch (err) {
      alert("Please enter a valid URL (e.g., https://example.com)");
    }
  };

  const removeUrl = (actor: string, urlToRemove: string) => {
    setTrustedSources(prev => {
      const currentUrls = prev[actor] || [];
      const updatedUrls = currentUrls.filter(u => u !== urlToRemove);
      if (updatedUrls.length === 0) {
        const { [actor]: _, ...rest } = prev;
        return rest;
      }
      return { ...prev, [actor]: updatedUrls };
    });
  };

  // --- FILE HANDLING ---

  const parsePDF = async (file: File): Promise<string> => {
    const arrayBuffer = await file.arrayBuffer();
    // Handle module default export mismatch
    const lib = pdfjsLib.getDocument ? pdfjsLib : (pdfjsLib as any).default;
    
    if (!lib || !lib.getDocument) {
      throw new Error("PDF Library failed to load properly. Please refresh.");
    }

    const pdf = await lib.getDocument({ data: arrayBuffer }).promise;
    let fullText = '';
    
    for (let i = 1; i <= pdf.numPages; i++) {
      const page = await pdf.getPage(i);
      const textContent = await page.getTextContent();
      const pageText = textContent.items.map((item: any) => item.str).join(' ');
      fullText += pageText + '\n';
    }
    return fullText;
  };

  const parseCSV = async (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const data = new Uint8Array(e.target?.result as ArrayBuffer);
          const workbook = XLSX.read(data, { type: 'array' });
          const sheetName = workbook.SheetNames[0];
          const worksheet = workbook.Sheets[sheetName];
          const csvText = XLSX.utils.sheet_to_csv(worksheet);
          resolve(csvText);
        } catch (error) {
          reject(error);
        }
      };
      reader.onerror = reject;
      reader.readAsArrayBuffer(file);
    });
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !selectedActor.trim()) return;

    setIsProcessingFile(true);
    try {
      let content = '';
      const type = file.name.endsWith('.pdf') ? 'pdf' : 'csv';

      if (type === 'pdf') {
        content = await parsePDF(file);
      } else {
        content = await parseCSV(file);
      }

      const normalizedActor = selectedActor.trim().toLowerCase();
      const newFile: TrustedFile = {
        name: file.name,
        type,
        content,
        timestamp: Date.now()
      };

      setTrustedFiles(prev => {
        const currentFiles = prev[normalizedActor] || [];
        // Prevent dupes by name
        const filtered = currentFiles.filter(f => f.name !== file.name);
        return {
          ...prev,
          [normalizedActor]: [...filtered, newFile]
        };
      });

    } catch (error) {
      console.error(error);
      alert("Error parsing file. Please ensure it is a valid PDF or CSV.");
    } finally {
      setIsProcessingFile(false);
      // Reset input
      e.target.value = '';
    }
  };

  const removeFile = (actor: string, fileName: string) => {
    setTrustedFiles(prev => {
      const currentFiles = prev[actor] || [];
      const updatedFiles = currentFiles.filter(f => f.name !== fileName);
      if (updatedFiles.length === 0) {
        const { [actor]: _, ...rest } = prev;
        return rest;
      }
      return { ...prev, [actor]: updatedFiles };
    });
  };

  // --- VIEW HELPERS ---

  const getActorsList = () => {
    const urlActors = Object.keys(trustedSources);
    const fileActors = Object.keys(trustedFiles);
    const allActors = Array.from(new Set([...urlActors, ...fileActors]));
    
    if (!searchTerm) return allActors;
    return allActors.filter(a => a.toLowerCase().includes(searchTerm.toLowerCase()));
  };

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
          {getActorsList().length === 0 && (
            <div className="text-center p-4 text-slate-500 text-sm italic">
              No custom sources configured.
            </div>
          )}
          {getActorsList().map(actor => (
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
              {(trustedFiles[actor]?.length ?? 0) > 0 && <FileText className="w-3 h-3 opacity-50" />}
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
                        accept=".pdf,.csv" 
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
                        <span className="text-xs text-slate-500 mt-1">Files are parsed locally and used for strict validation</span>
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
               {activeTab === 'urls' && selectedActor && trustedSources[selectedActor.toLowerCase()]?.map((url, idx) => (
                <div key={`url-${idx}`} className="flex items-center justify-between p-4 bg-slate-900/50 border border-slate-800 rounded-lg group hover:border-slate-700">
                  <div className="flex items-center gap-3 overflow-hidden">
                    <Globe className="w-4 h-4 text-slate-500 flex-shrink-0" />
                    <a href={url} target="_blank" rel="noopener noreferrer" className="text-slate-300 text-sm truncate hover:text-green-400">
                      {url}
                    </a>
                  </div>
                  <button onClick={() => removeUrl(selectedActor.toLowerCase(), url)} className="p-2 text-slate-600 hover:text-red-400 opacity-0 group-hover:opacity-100">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}

              {/* Display Files */}
              {activeTab === 'files' && selectedActor && trustedFiles[selectedActor.toLowerCase()]?.map((file, idx) => (
                <div key={`file-${idx}`} className="flex items-center justify-between p-4 bg-slate-900/50 border border-slate-800 rounded-lg group hover:border-slate-700">
                  <div className="flex items-center gap-3 overflow-hidden">
                    <FileText className="w-4 h-4 text-blue-500 flex-shrink-0" />
                    <div className="flex flex-col">
                       <span className="text-slate-300 text-sm truncate">{file.name}</span>
                       <span className="text-[10px] text-slate-500">{Math.round(file.content.length / 1024)} KB extracted • {new Date(file.timestamp).toLocaleDateString()}</span>
                    </div>
                  </div>
                  <button onClick={() => removeFile(selectedActor.toLowerCase(), file.name)} className="p-2 text-slate-600 hover:text-red-400 opacity-0 group-hover:opacity-100">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              ))}

              {selectedActor && 
               ((activeTab === 'urls' && (!trustedSources[selectedActor.toLowerCase()]?.length)) || 
                (activeTab === 'files' && (!trustedFiles[selectedActor.toLowerCase()]?.length))) && (
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