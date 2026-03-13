"use client";

import React, { useState, useRef, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { 
  ChatSession, 
  ChatMessage, 
  CreditInfo,
  Scan 
} from "@/lib/types";

interface InteractiveChatProps {
  scan: Scan;
  creditInfo: CreditInfo;
  onChatSessionUpdate: (session: ChatSession) => void;
  isOpen: boolean;
  onToggle: () => void;
}

const suggestedQuestions = [
  "How could this vulnerability be exploited?",
  "What's the attack chain for this finding?", 
  "How serious is this security issue?",
  "What data could be compromised?",
  "Are there any mitigating factors?",
  "What's the recommended remediation priority?"
];

export default function InteractiveChat({ 
  scan, 
  creditInfo, 
  onChatSessionUpdate,
  isOpen,
  onToggle
}: InteractiveChatProps) {
  const [session, setSession] = useState<ChatSession | null>(null);
  const [currentMessage, setCurrentMessage] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [showCostPreview, setShowCostPreview] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const cost = creditInfo.costs.chat_message;
  const canAfford = creditInfo.balance >= cost;

  const scrollToBottom = (): void => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [session?.messages]);

  useEffect(() => {
    if (isOpen && !session) {
      initializeSession();
    }
  }, [isOpen, session]);

  const initializeSession = async (): Promise<void> => {
    try {
      const response = await fetch("/api/v1/interactive/sessions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          scan_id: scan.id
        })
      });

      if (!response.ok) {
        throw new Error("Failed to create chat session");
      }

      const newSession: ChatSession = await response.json();
      setSession(newSession);
      onChatSessionUpdate(newSession);
    } catch (error) {
      console.error("Session initialization error:", error);
    }
  };

  const sendMessage = async (message: string): Promise<void> => {
    if (!session || !message.trim() || !canAfford) return;

    setIsSending(true);
    setShowCostPreview(false);

    // Optimistically add user message
    const userMessage: ChatMessage = {
      id: `temp-${Date.now()}`,
      role: "user",
      content: message.trim(),
      timestamp: new Date().toISOString()
    };

    const updatedSession = {
      ...session,
      messages: [...session.messages, userMessage]
    };
    setSession(updatedSession);
    setCurrentMessage("");

    try {
      const response = await fetch(`/api/v1/interactive/sessions/${session.id}/messages`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: message.trim()
        })
      });

      if (!response.ok) {
        throw new Error("Failed to send message");
      }

      const updatedSessionFromServer: ChatSession = await response.json();
      setSession(updatedSessionFromServer);
      onChatSessionUpdate(updatedSessionFromServer);
    } catch (error) {
      console.error("Message send error:", error);
      // Revert optimistic update on error
      setSession(session);
    } finally {
      setIsSending(false);
    }
  };

  const handleSuggestedQuestion = (question: string): void => {
    setCurrentMessage(question);
    setShowCostPreview(true);
  };

  const handleKeyPress = (e: React.KeyboardEvent): void => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      if (currentMessage.trim() && canAfford && !isSending) {
        sendMessage(currentMessage);
      }
    }
  };

  const formatMessage = (content: string): JSX.Element => {
    // Simple markdown rendering for code blocks
    const codeBlockRegex = /```(\w+)?\n([\s\S]*?)\n```/g;
    const inlineCodeRegex = /`([^`]+)`/g;
    
    let formatted = content;
    
    // Replace code blocks
    formatted = formatted.replace(codeBlockRegex, (match, language, code) => {
      return `<div class="code-block my-2 p-3 bg-gray-800/50 border border-gray-700 rounded font-mono text-sm overflow-x-auto"><pre><code>${code}</code></pre></div>`;
    });
    
    // Replace inline code
    formatted = formatted.replace(inlineCodeRegex, (match, code) => {
      return `<code class="bg-gray-800/50 px-1 py-0.5 rounded text-sm font-mono text-brand-400">${code}</code>`;
    });

    return (
      <div 
        className="prose prose-sm max-w-none text-gray-300"
        dangerouslySetInnerHTML={{ __html: formatted }}
      />
    );
  };

  if (!isOpen) {
    return (
      <div className="fixed bottom-6 right-6 z-50">
        <Button
          onClick={onToggle}
          className="flex items-center gap-2 shadow-lg bg-brand-600 hover:bg-brand-700"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                  d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
          </svg>
          Ask AI about scan
        </Button>
      </div>
    );
  }

  return (
    <div className="fixed bottom-6 right-6 w-96 h-[600px] z-50 border border-gray-700 rounded-lg bg-gray-900 shadow-2xl flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-700">
        <div>
          <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                    d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
            </svg>
            Security Assistant
          </h3>
          <p className="text-xs text-gray-500">
            Balance: {creditInfo.balance} credits • AI guidance only
          </p>
        </div>
        <Button
          onClick={onToggle}
          variant="ghost"
          size="sm"
          className="h-8 w-8 p-0"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                  d="M6 18L18 6M6 6l12 12" />
          </svg>
        </Button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {!session?.messages.length ? (
          <div className="text-center py-8">
            <svg className="w-8 h-8 mx-auto mb-3 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                    d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
            </svg>
            <p className="text-sm text-gray-400 mb-4">
              Ask questions about your scan results
            </p>
            
            {/* Suggested questions */}
            <div className="space-y-2">
              <p className="text-xs font-medium text-gray-500 mb-2">
                Suggested questions:
              </p>
              {suggestedQuestions.slice(0, 3).map((question, index) => (
                <button
                  key={index}
                  onClick={() => handleSuggestedQuestion(question)}
                  className="block w-full text-left text-xs text-gray-400 hover:text-gray-300 p-2 rounded border border-gray-700 hover:border-gray-600 transition-colors"
                  disabled={!canAfford}
                >
                  {question}
                </button>
              ))}
            </div>
          </div>
        ) : (
          session.messages.map((message) => (
            <div
              key={message.id}
              className={`flex ${message.role === "user" ? "justify-end" : "justify-start"}`}
            >
              <div
                className={`max-w-[80%] rounded-lg p-3 ${
                  message.role === "user"
                    ? "bg-brand-600 text-white"
                    : "bg-gray-800 text-gray-300"
                }`}
              >
                {message.role === "user" ? (
                  <p className="text-sm">{message.content}</p>
                ) : (
                  formatMessage(message.content)
                )}
                
                <div className={`mt-2 flex items-center justify-between text-xs ${
                  message.role === "user" ? "text-brand-200" : "text-gray-500"
                }`}>
                  <span>
                    {new Date(message.timestamp).toLocaleTimeString()}
                  </span>
                  {message.credits_used && (
                    <span>{message.credits_used} credits</span>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
        
        {isSending && (
          <div className="flex justify-start">
            <div className="bg-gray-800 text-gray-300 rounded-lg p-3 flex items-center gap-2">
              <div className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
              <span className="text-sm">Thinking...</span>
            </div>
          </div>
        )}
        
        <div ref={messagesEndRef} />
      </div>

      {/* Cost preview */}
      {showCostPreview && (
        <div className="px-4 py-2 border-t border-gray-700 bg-blue-500/10">
          <div className="flex items-center justify-between text-xs">
            <span className="text-blue-300">
              This will cost {cost} credits
            </span>
            <Button
              onClick={() => setShowCostPreview(false)}
              variant="ghost"
              size="sm"
              className="h-6 px-2 text-xs text-gray-400"
            >
              Cancel
            </Button>
          </div>
        </div>
      )}

      {/* Input */}
      <div className="p-4 border-t border-gray-700">
        <div className="flex gap-2">
          <textarea
            value={currentMessage}
            onChange={(e) => setCurrentMessage(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder={canAfford ? "Ask about the security findings..." : "Insufficient credits"}
            disabled={isSending || !canAfford}
            className="flex-1 text-sm bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent resize-none"
            rows={2}
          />
          <Button
            onClick={() => sendMessage(currentMessage)}
            disabled={!currentMessage.trim() || isSending || !canAfford}
            size="sm"
            className="self-end"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                    d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
            </svg>
          </Button>
        </div>
        
        {currentMessage.trim() && (
          <div className="space-y-1">
            <div className="flex items-center justify-between text-xs text-gray-500">
              <span>
                Cost: {cost} credits
              </span>
              <span>
                Press Enter to send
              </span>
            </div>
            <div className="text-xs text-gray-400 italic">
              💡 AI responses are guidance only - verify security advice independently
            </div>
          </div>
        )}
      </div>
    </div>
  );
}