import React from 'react';
import { ViewState } from '../types';
import { ShieldAlert, MessageSquare, Radio, Hexagon, Database } from 'lucide-react';

interface SidebarProps {
  currentView: ViewState;
  onViewChange: (view: ViewState) => void;
}

const Sidebar: React.FC<SidebarProps> = ({ currentView, onViewChange }) => {
  const navItems = [
    { id: ViewState.THREAT_ACTORS, label: 'Threat Actors', icon: ShieldAlert },
    { id: ViewState.TRUSTED_SOURCES, label: 'Approved Sources', icon: Database },
    { id: ViewState.CHAT, label: 'Intel Chat', icon: MessageSquare },
    { id: ViewState.LIVE_FEED, label: 'Live Intel', icon: Radio },
  ];

  return (
    <div className="w-20 bg-slate-900 border-r border-slate-800 flex flex-col items-center py-6 z-50">
      <div className="mb-8 p-2 bg-yellow-500/10 rounded-full">
        <Hexagon className="w-8 h-8 text-yellow-500" />
      </div>
      
      <div className="flex flex-col gap-6 w-full px-2">
        {navItems.map((item) => {
          const isActive = currentView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onViewChange(item.id)}
              className={`flex flex-col items-center justify-center p-3 rounded-xl transition-all duration-200 group relative
                ${isActive 
                  ? 'bg-yellow-500 text-slate-900 shadow-[0_0_15px_rgba(234,179,8,0.3)]' 
                  : 'text-slate-400 hover:text-yellow-400 hover:bg-slate-800'
                }`}
            >
              <item.icon className="w-6 h-6 mb-1" />
              <span className="text-[10px] font-medium text-center leading-tight">{item.label}</span>
              
              {isActive && (
                <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-8 bg-yellow-200 rounded-r-full -ml-2" />
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
};

export default Sidebar;