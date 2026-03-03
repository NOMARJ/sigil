"use client";

import { useState, useEffect } from "react";
import { useAuth } from "@/lib/auth";
import PlanGate from "@/components/PlanGate";
import type { ForgeTool, TrackToolRequest } from "@/lib/types";

// Mock data for development - replace with API calls
const mockTools: ForgeTool[] = [
  {
    id: "1",
    name: "LangChain",
    description: "Framework for developing applications powered by language models",
    category: "AI Framework",
    repository_url: "https://github.com/langchain-ai/langchain",
    documentation_url: "https://python.langchain.com/",
    version: "0.1.6",
    risk_score: 2.1,
    last_scan_id: "scan_123",
    tracked_at: "2024-03-01T10:30:00Z",
    created_by: "user_123"
  },
  {
    id: "2",
    name: "CrewAI",
    description: "Framework for orchestrating role-playing, autonomous AI agents",
    category: "Agent Framework",
    repository_url: "https://github.com/joaomdmoura/crewAI",
    documentation_url: "https://docs.crewai.com/",
    version: "0.22.5",
    risk_score: 1.8,
    tracked_at: "2024-03-02T14:15:00Z",
    created_by: "user_123"
  },
  {
    id: "3",
    name: "AutoGen",
    description: "Enable next-gen large language model applications with multi-agent conversation framework",
    category: "Agent Framework", 
    repository_url: "https://github.com/microsoft/autogen",
    documentation_url: "https://microsoft.github.io/autogen/",
    version: "0.2.16",
    risk_score: 1.5,
    tracked_at: "2024-03-03T09:45:00Z",
    created_by: "user_123"
  }
];

interface ToolCardProps {
  tool: ForgeTool;
  onUntrack: (toolId: string) => void;
}

function ToolCard({ tool, onUntrack }: ToolCardProps) {
  const getRiskColor = (score?: number) => {
    if (!score) return "text-gray-500";
    if (score < 2) return "text-green-400";
    if (score < 4) return "text-yellow-400";
    return "text-red-400";
  };

  const getRiskLabel = (score?: number) => {
    if (!score) return "Unknown";
    if (score < 2) return "Low Risk";
    if (score < 4) return "Medium Risk";
    return "High Risk";
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 hover:border-gray-700 transition-colors">
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1">
          <h3 className="text-lg font-semibold text-white mb-2">{tool.name}</h3>
          <p className="text-gray-400 text-sm mb-3">{tool.description}</p>
          <div className="flex items-center gap-4 text-sm">
            <span className="bg-gray-800 text-gray-300 px-2 py-1 rounded">
              {tool.category}
            </span>
            <span className="text-gray-500">v{tool.version}</span>
            <span className={`font-medium ${getRiskColor(tool.risk_score)}`}>
              {getRiskLabel(tool.risk_score)}
            </span>
          </div>
        </div>
        <button
          onClick={() => onUntrack(tool.id)}
          className="text-gray-500 hover:text-red-400 transition-colors p-1"
          title="Untrack tool"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1-1H9a1 1 0 00-1 1v3M4 7h16" />
          </svg>
        </button>
      </div>

      <div className="flex items-center justify-between pt-4 border-t border-gray-800">
        <div className="flex items-center gap-4">
          <a 
            href={tool.repository_url}
            target="_blank" 
            rel="noopener noreferrer"
            className="text-brand-400 hover:text-brand-300 text-sm font-medium transition-colors"
          >
            Repository →
          </a>
          {tool.documentation_url && (
            <a 
              href={tool.documentation_url}
              target="_blank" 
              rel="noopener noreferrer"
              className="text-gray-400 hover:text-gray-300 text-sm transition-colors"
            >
              Docs →
            </a>
          )}
        </div>
        
        {tool.last_scan_id && (
          <button className="text-gray-400 hover:text-white text-sm font-medium transition-colors">
            View Scan →
          </button>
        )}
      </div>
    </div>
  );
}

interface AddToolModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (tool: TrackToolRequest) => void;
}

function AddToolModal({ isOpen, onClose, onSubmit }: AddToolModalProps) {
  const [formData, setFormData] = useState<TrackToolRequest>({
    name: "",
    repository_url: "",
    description: "",
    category: "",
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (formData.name && formData.repository_url) {
      onSubmit(formData);
      setFormData({ name: "", repository_url: "", description: "", category: "" });
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex items-center justify-center min-h-screen px-4">
        <div className="fixed inset-0 bg-black/50" onClick={onClose} />
        <div className="relative bg-gray-900 border border-gray-800 rounded-lg w-full max-w-md p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Track New Tool</h3>
          
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Tool Name
              </label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
                placeholder="e.g., LangChain"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Repository URL
              </label>
              <input
                type="url"
                value={formData.repository_url}
                onChange={(e) => setFormData(prev => ({ ...prev, repository_url: e.target.value }))}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
                placeholder="https://github.com/..."
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Description
              </label>
              <textarea
                value={formData.description}
                onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
                rows={3}
                placeholder="Brief description of the tool..."
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Category
              </label>
              <select
                value={formData.category}
                onChange={(e) => setFormData(prev => ({ ...prev, category: e.target.value }))}
                className="w-full px-3 py-2 bg-gray-800 border border-gray-700 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
              >
                <option value="">Select category...</option>
                <option value="AI Framework">AI Framework</option>
                <option value="Agent Framework">Agent Framework</option>
                <option value="Model Library">Model Library</option>
                <option value="Data Processing">Data Processing</option>
                <option value="Deployment">Deployment</option>
                <option value="Other">Other</option>
              </select>
            </div>

            <div className="flex gap-3 pt-4">
              <button
                type="submit"
                className="flex-1 bg-brand-600 hover:bg-brand-700 text-white font-medium py-2 px-4 rounded-md transition-colors"
              >
                Track Tool
              </button>
              <button
                type="button"
                onClick={onClose}
                className="flex-1 bg-gray-800 hover:bg-gray-700 text-gray-300 font-medium py-2 px-4 rounded-md transition-colors"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}

export default function MyToolsPage() {
  const { user } = useAuth();
  const [tools, setTools] = useState<ForgeTool[]>([]);
  const [loading, setLoading] = useState(true);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("");

  useEffect(() => {
    // Simulate loading tools from API
    setTimeout(() => {
      setTools(mockTools);
      setLoading(false);
    }, 500);
  }, []);

  const handleTrackTool = (toolData: TrackToolRequest) => {
    const newTool: ForgeTool = {
      id: Date.now().toString(),
      name: toolData.name,
      repository_url: toolData.repository_url,
      description: toolData.description || "",
      category: toolData.category || "other",
      version: "latest",
      tracked_at: new Date().toISOString(),
      created_by: user?.id || "",
    };
    setTools(prev => [newTool, ...prev]);
  };

  const handleUntrackTool = (toolId: string) => {
    setTools(prev => prev.filter(tool => tool.id !== toolId));
  };

  const filteredTools = tools.filter(tool => {
    const matchesSearch = tool.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         tool.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = !selectedCategory || tool.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  const categories = Array.from(new Set(tools.map(tool => tool.category)));

  if (!user?.plan) {
    return <div>Loading...</div>;
  }

  return (
    <PlanGate requiredPlan="pro" currentPlan={user.plan}>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">My Tools</h1>
            <p className="text-gray-400 mt-1">
              Track and monitor security for your AI tools and frameworks
            </p>
          </div>
          <button
            onClick={() => setIsAddModalOpen(true)}
            className="inline-flex items-center gap-2 px-4 py-2 bg-brand-600 hover:bg-brand-700 text-white font-medium rounded-md transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
            </svg>
            Track New Tool
          </button>
        </div>

        {/* Filters */}
        <div className="flex gap-4 items-center">
          <div className="flex-1">
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search tools..."
              className="w-full px-4 py-2 bg-gray-900 border border-gray-800 rounded-md text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
            />
          </div>
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="px-4 py-2 bg-gray-900 border border-gray-800 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
          >
            <option value="">All Categories</option>
            {categories.map(category => (
              <option key={category} value={category}>{category}</option>
            ))}
          </select>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <div className="text-2xl font-bold text-white">{tools.length}</div>
            <div className="text-gray-400 text-sm">Tracked Tools</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <div className="text-2xl font-bold text-green-400">
              {tools.filter(t => (t.risk_score || 0) < 2).length}
            </div>
            <div className="text-gray-400 text-sm">Low Risk</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <div className="text-2xl font-bold text-yellow-400">
              {tools.filter(t => (t.risk_score || 0) >= 2 && (t.risk_score || 0) < 4).length}
            </div>
            <div className="text-gray-400 text-sm">Medium Risk</div>
          </div>
        </div>

        {/* Tools Grid */}
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="w-8 h-8 border-2 border-brand-600 border-t-transparent rounded-full animate-spin"></div>
          </div>
        ) : filteredTools.length > 0 ? (
          <div className="grid gap-6">
            {filteredTools.map((tool) => (
              <ToolCard key={tool.id} tool={tool} onUntrack={handleUntrackTool} />
            ))}
          </div>
        ) : (
          <div className="text-center py-12">
            <svg className="w-16 h-16 text-gray-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
            </svg>
            <h3 className="text-lg font-medium text-gray-400 mb-2">No tools tracked yet</h3>
            <p className="text-gray-500 mb-6">Start tracking AI tools and frameworks to monitor their security status.</p>
            <button
              onClick={() => setIsAddModalOpen(true)}
              className="inline-flex items-center gap-2 px-4 py-2 bg-brand-600 hover:bg-brand-700 text-white font-medium rounded-md transition-colors"
            >
              Track Your First Tool
            </button>
          </div>
        )}

        {/* Add Tool Modal */}
        <AddToolModal
          isOpen={isAddModalOpen}
          onClose={() => setIsAddModalOpen(false)}
          onSubmit={handleTrackTool}
        />
      </div>
    </PlanGate>
  );
}