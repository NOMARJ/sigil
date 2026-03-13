'use client';

import { 
  ShieldCheckIcon,
  EyeIcon,
  DocumentMagnifyingGlassIcon,
  ChartBarIcon
} from '@heroicons/react/24/outline';

const trustFeatures = [
  {
    icon: ShieldCheckIcon,
    title: 'Security Scanning',
    description: 'Every tool is automatically scanned for vulnerabilities, malicious code, and security issues.',
    color: 'text-red-600'
  },
  {
    icon: DocumentMagnifyingGlassIcon,
    title: 'Code Analysis',
    description: 'Deep static analysis examines code quality, dependencies, and potential risks.',
    color: 'text-blue-600'
  },
  {
    icon: EyeIcon,
    title: 'Community Trust',
    description: 'Usage patterns, reviews, and community feedback contribute to trust scores.',
    color: 'text-green-600'
  },
  {
    icon: ChartBarIcon,
    title: 'Trust Score',
    description: 'Comprehensive 0-100 score combining security, quality, and community factors.',
    color: 'text-purple-600'
  },
];

export function TrustSection() {
  return (
    <section className="py-20 bg-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-3xl font-bold text-gray-900 sm:text-4xl mb-4">
            Trust Through Transparency
          </h2>
          <p className="text-lg text-gray-600 max-w-3xl mx-auto">
            Every tool in Forge is automatically scanned and evaluated using our comprehensive 
            security and quality framework. No tool goes unverified.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8 mb-16">
          {trustFeatures.map((feature, index) => {
            const IconComponent = feature.icon;
            return (
              <div key={feature.title} className="text-center group">
                <div className="relative mb-6">
                  <div className={`inline-flex p-3 rounded-full bg-gray-100 group-hover:bg-gray-200 transition-colors`}>
                    <IconComponent className={`h-8 w-8 ${feature.color}`} />
                  </div>
                  
                  {/* Connection lines */}
                  {index < trustFeatures.length - 1 && (
                    <div className="hidden lg:block absolute top-1/2 left-full w-full h-0.5 bg-gradient-to-r from-gray-300 to-transparent"></div>
                  )}
                </div>
                
                <h3 className="text-lg font-semibold text-gray-900 mb-3">
                  {feature.title}
                </h3>
                <p className="text-gray-600 text-sm leading-relaxed">
                  {feature.description}
                </p>
              </div>
            );
          })}
        </div>

        {/* Trust Score Visualization */}
        <div className="bg-gradient-to-br from-gray-50 to-blue-50 rounded-2xl p-8 lg:p-12">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-center">
            <div>
              <h3 className="text-2xl font-bold text-gray-900 mb-6">
                How Trust Scores Work
              </h3>
              
              <div className="space-y-4">
                <div className="flex items-center justify-between p-3 bg-white rounded-lg shadow-sm">
                  <span className="font-medium text-gray-700">Security Scan</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-20 h-2 bg-gray-200 rounded-full overflow-hidden">
                      <div className="w-4/5 h-full bg-green-500 rounded-full"></div>
                    </div>
                    <span className="text-sm font-medium text-gray-900">40%</span>
                  </div>
                </div>
                
                <div className="flex items-center justify-between p-3 bg-white rounded-lg shadow-sm">
                  <span className="font-medium text-gray-700">Code Quality</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-20 h-2 bg-gray-200 rounded-full overflow-hidden">
                      <div className="w-3/4 h-full bg-blue-500 rounded-full"></div>
                    </div>
                    <span className="text-sm font-medium text-gray-900">30%</span>
                  </div>
                </div>
                
                <div className="flex items-center justify-between p-3 bg-white rounded-lg shadow-sm">
                  <span className="font-medium text-gray-700">Community</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-20 h-2 bg-gray-200 rounded-full overflow-hidden">
                      <div className="w-3/5 h-full bg-purple-500 rounded-full"></div>
                    </div>
                    <span className="text-sm font-medium text-gray-900">20%</span>
                  </div>
                </div>
                
                <div className="flex items-center justify-between p-3 bg-white rounded-lg shadow-sm">
                  <span className="font-medium text-gray-700">Maintenance</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-20 h-2 bg-gray-200 rounded-full overflow-hidden">
                      <div className="w-1/2 h-full bg-yellow-500 rounded-full"></div>
                    </div>
                    <span className="text-sm font-medium text-gray-900">10%</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Trust Score Demo */}
            <div className="flex justify-center">
              <div className="relative">
                <div className="w-48 h-48 rounded-full border-8 border-gray-200 flex items-center justify-center">
                  <div className="text-center">
                    <div className="text-4xl font-bold text-sigil-600 mb-2">85</div>
                    <div className="text-sm font-medium text-gray-600">Trust Score</div>
                    <div className="text-xs text-green-600 mt-1">Excellent</div>
                  </div>
                </div>
                
                {/* Score ring */}
                <svg className="absolute inset-0 w-48 h-48 transform -rotate-90">
                  <circle
                    cx="96"
                    cy="96"
                    r="88"
                    stroke="currentColor"
                    strokeWidth="8"
                    fill="none"
                    className="text-sigil-600"
                    strokeDasharray={`${85 * 5.5} 1000`}
                  />
                </svg>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}