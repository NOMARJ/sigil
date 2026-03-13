'use client';

import { Button } from '@/components/ui/Button';
import { 
  RocketLaunchIcon, 
  DocumentTextIcon,
  CodeBracketIcon
} from '@heroicons/react/24/outline';

export function CTASection() {
  return (
    <section className="py-20 bg-gradient-to-br from-sigil-600 to-blue-700">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center">
          <h2 className="text-3xl font-bold text-white sm:text-4xl mb-6">
            Ready to Build with Confidence?
          </h2>
          <p className="text-xl text-sigil-100 max-w-3xl mx-auto mb-12">
            Join thousands of developers using Sigil Forge to discover, 
            evaluate, and deploy AI agent tools safely.
          </p>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-12">
            <div className="text-center">
              <div className="inline-flex p-4 bg-white bg-opacity-20 rounded-full mb-4">
                <RocketLaunchIcon className="h-8 w-8 text-white" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">
                Start Building
              </h3>
              <p className="text-sigil-100 text-sm">
                Browse our catalog of verified tools and start building your AI agent today.
              </p>
            </div>
            
            <div className="text-center">
              <div className="inline-flex p-4 bg-white bg-opacity-20 rounded-full mb-4">
                <DocumentTextIcon className="h-8 w-8 text-white" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">
                Learn More
              </h3>
              <p className="text-sigil-100 text-sm">
                Read our documentation to understand trust scores and security scanning.
              </p>
            </div>
            
            <div className="text-center">
              <div className="inline-flex p-4 bg-white bg-opacity-20 rounded-full mb-4">
                <CodeBracketIcon className="h-8 w-8 text-white" />
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">
                Contribute
              </h3>
              <p className="text-sigil-100 text-sm">
                Submit your own tools and help grow the trusted AI agent ecosystem.
              </p>
            </div>
          </div>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button 
              size="lg" 
              variant="secondary" 
              href="/discover"
              className="bg-white text-sigil-600 hover:bg-gray-100 border-0 text-lg px-8"
            >
              <RocketLaunchIcon className="h-5 w-5 mr-2" />
              Start Exploring
            </Button>
            <Button 
              size="lg" 
              variant="outline" 
              href="/docs"
              className="border-white text-white hover:bg-white hover:text-sigil-600 text-lg px-8"
            >
              <DocumentTextIcon className="h-5 w-5 mr-2" />
              Read Documentation
            </Button>
          </div>
        </div>
      </div>
    </section>
  );
}