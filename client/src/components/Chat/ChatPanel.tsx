import React, { useState, useRef, useEffect } from 'react';
import { ChatMessage } from '../../types';
import { Send, Bot, User, Sparkles } from 'lucide-react';
import { chatWithAI } from '../../services/apiService';

const ChatPanel: React.FC = () => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      role: 'model',
      text: 'Hello, analyst. I am the HivePro Intel AI. You can ask me about specific threat actors, recent vulnerabilities, or general cybersecurity trends.',
      timestamp: Date.now()
    }
  ]);
  const [input, setInput] = useState('');
  const [isThinking, setIsThinking] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isThinking) return;

    const userMsg: ChatMessage = {
      id: Date.now().toString(),
      role: 'user',
      text: input,
      timestamp: Date.now()
    };

    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setIsThinking(true);

    const responseText = await chatWithAI(input);

    const botMsg: ChatMessage = {
      id: (Date.now() + 1).toString(),
      role: 'model',
      text: responseText,
      timestamp: Date.now()
    };

    setMessages(prev => [...prev, botMsg]);
    setIsThinking(false);
  };

  return (
    <div className="flex flex-col h-full bg-slate-950 w-full relative">
      <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 pointer-events-none"></div>

      {/* Header */}
      <div className="p-6 border-b border-slate-800 bg-slate-900/50 backdrop-blur z-10">
        <h2 className="text-xl font-bold text-white flex items-center gap-3">
          <Sparkles className="w-5 h-5 text-yellow-500" />
          Intelligence Analyst Chat
        </h2>
        <p className="text-slate-400 text-sm mt-1">Powered by Gemini 3 Flash</p>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6 z-10">
        {messages.map((msg) => {
          const isUser = msg.role === 'user';
          return (
            <div key={msg.id} className={`flex ${isUser ? 'justify-end' : 'justify-start'}`}>
              <div className={`flex max-w-[80%] gap-4 ${isUser ? 'flex-row-reverse' : 'flex-row'}`}>
                <div className={`w-10 h-10 rounded-full flex items-center justify-center flex-shrink-0
                  ${isUser ? 'bg-slate-700' : 'bg-yellow-600'}`}>
                  {isUser ? <User className="w-5 h-5 text-slate-300" /> : <Bot className="w-6 h-6 text-slate-900" />}
                </div>

                <div className={`p-4 rounded-2xl text-sm leading-relaxed shadow-lg
                  ${isUser
                    ? 'bg-slate-800 text-slate-100 rounded-tr-none border border-slate-700'
                    : 'bg-slate-900 text-slate-200 rounded-tl-none border border-slate-800'
                  }`}>
                  {msg.text.split('\n').map((line, i) => (
                    <p key={i} className={i > 0 ? 'mt-2' : ''}>{line}</p>
                  ))}
                  <span className="text-[10px] text-slate-500 mt-2 block opacity-70">
                    {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                </div>
              </div>
            </div>
          );
        })}
        {isThinking && (
          <div className="flex justify-start">
             <div className="flex max-w-[80%] gap-4">
                <div className="w-10 h-10 rounded-full bg-yellow-600 flex items-center justify-center flex-shrink-0">
                  <Bot className="w-6 h-6 text-slate-900" />
                </div>
                <div className="bg-slate-900 p-4 rounded-2xl rounded-tl-none border border-slate-800 flex items-center gap-2">
                   <div className="w-2 h-2 bg-yellow-500 rounded-full animate-bounce" style={{ animationDelay: '0s' }} />
                   <div className="w-2 h-2 bg-yellow-500 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }} />
                   <div className="w-2 h-2 bg-yellow-500 rounded-full animate-bounce" style={{ animationDelay: '0.4s' }} />
                </div>
             </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="p-6 bg-slate-900/80 border-t border-slate-800 z-10">
        <form onSubmit={handleSend} className="relative max-w-4xl mx-auto">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about TTPs, Indicators of Compromise, or analysis..."
            className="w-full bg-slate-950 text-white rounded-xl py-4 pl-6 pr-14 border border-slate-700 focus:border-yellow-500 focus:ring-1 focus:ring-yellow-500 outline-none shadow-xl transition-all"
            disabled={isThinking}
          />
          <button
            type="submit"
            disabled={!input.trim() || isThinking}
            className="absolute right-3 top-1/2 -translate-y-1/2 p-2 bg-yellow-600 rounded-lg hover:bg-yellow-500 text-slate-900 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Send className="w-5 h-5" />
          </button>
        </form>
      </div>
    </div>
  );
};

export default ChatPanel;
