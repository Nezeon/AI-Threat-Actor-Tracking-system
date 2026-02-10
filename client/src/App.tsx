import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import ThreatActorPanel from './components/ThreatActor/ThreatActorPanel';
import ChatPanel from './components/Chat/ChatPanel';
import LiveFeedPanel from './components/LiveFeed/LiveFeedPanel';
import TrustedSourcesPanel from './components/TrustedSources/TrustedSourcesPanel';
import { ViewState } from './types';

const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<ViewState>(ViewState.THREAT_ACTORS);

  const renderContent = () => {
    switch (currentView) {
      case ViewState.THREAT_ACTORS:
        return <ThreatActorPanel />;
      case ViewState.CHAT:
        return <ChatPanel />;
      case ViewState.LIVE_FEED:
        return <LiveFeedPanel />;
      case ViewState.TRUSTED_SOURCES:
        return <TrustedSourcesPanel />;
      default:
        return <ThreatActorPanel />;
    }
  };

  return (
    <div className="flex h-screen w-screen bg-slate-950 text-slate-200 overflow-hidden font-sans">
      <Sidebar currentView={currentView} onViewChange={setCurrentView} />
      <main className="flex-1 h-full overflow-hidden relative">
        {renderContent()}
      </main>
    </div>
  );
};

export default App;
