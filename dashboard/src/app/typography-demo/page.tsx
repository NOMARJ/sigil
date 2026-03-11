'use client';

export default function TypographyDemo() {
  return (
    <div className="min-h-screen p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-semibold mb-8" style={{ color: 'var(--color-text-primary)' }}>
          Improved Typography & Readability
        </h1>
        
        {/* Comparison Card */}
        <div className="card mb-8">
          <div className="card-header">
            <h2 className="section-header">Text Contrast Improvements</h2>
          </div>
          <div className="card-body space-y-4">
            <div>
              <p className="text-sm font-medium mb-2" style={{ color: 'var(--color-text-subtle)' }}>
                PRIMARY TEXT (Headers)
              </p>
              <p className="text-xl" style={{ color: 'var(--color-text-primary)' }}>
                Pure white (#ffffff) for maximum contrast
              </p>
            </div>
            
            <div>
              <p className="text-sm font-medium mb-2" style={{ color: 'var(--color-text-subtle)' }}>
                SECONDARY TEXT (Body)
              </p>
              <p style={{ color: 'var(--color-text-secondary)' }}>
                Light gray (#e2e8f0) - Much more readable than before. This is the main body text color that appears throughout the dashboard.
              </p>
            </div>
            
            <div>
              <p className="text-sm font-medium mb-2" style={{ color: 'var(--color-text-subtle)' }}>
                MUTED TEXT (Labels)
              </p>
              <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
                Medium gray (#94a3b8) - Still visible but de-emphasized for supplementary information
              </p>
            </div>
            
            <div>
              <p className="text-sm font-medium mb-2" style={{ color: 'var(--color-text-subtle)' }}>
                SUBTLE TEXT
              </p>
              <p className="text-sm" style={{ color: 'var(--color-text-subtle)' }}>
                Light subtle (#cbd5e1) - For labels and less important UI elements
              </p>
            </div>
          </div>
        </div>

        {/* AI Insights Example */}
        <div className="card mb-8">
          <div className="card-header">
            <h2 className="section-header">AI Insights Example</h2>
          </div>
          <div className="card-body">
            <div className="flex items-start gap-4">
              <div className="p-2 rounded-lg" style={{ background: 'var(--color-accent)/10' }}>
                <svg className="w-6 h-6" style={{ color: 'var(--color-accent)' }} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                </svg>
              </div>
              <div className="flex-1">
                <h3 className="font-semibold mb-2" style={{ color: 'var(--color-text-primary)' }}>
                  AI insights appear on scan results
                </h3>
                <p style={{ color: 'var(--color-text-secondary)' }}>
                  Run a scan on a package or repository to get AI-powered threat analysis, zero-day detection, and remediation suggestions.
                </p>
                <p className="text-sm mt-2" style={{ color: 'var(--color-text-muted)' }}>
                  Pro feature • Available on your current plan
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Font Weights */}
        <div className="card">
          <div className="card-header">
            <h2 className="section-header">Font Weight Scale</h2>
          </div>
          <div className="card-body space-y-3">
            <p className="font-normal" style={{ color: 'var(--color-text-secondary)' }}>
              Regular (400) - Standard body text
            </p>
            <p className="font-medium" style={{ color: 'var(--color-text-secondary)' }}>
              Medium (500) - Labels and UI elements
            </p>
            <p className="font-semibold" style={{ color: 'var(--color-text-secondary)' }}>
              Semibold (600) - Headers and emphasis
            </p>
            <p className="font-bold" style={{ color: 'var(--color-text-secondary)' }}>
              Bold (700) - Strong emphasis (rarely used)
            </p>
          </div>
        </div>

        {/* Sample Content */}
        <div className="mt-8 p-6 rounded-lg" style={{ background: 'var(--color-bg-secondary)' }}>
          <h3 className="text-lg font-semibold mb-3" style={{ color: 'var(--color-text-primary)' }}>
            Sample Dashboard Content
          </h3>
          <p className="mb-4" style={{ color: 'var(--color-text-secondary)' }}>
            This demonstrates the improved readability with proper contrast ratios. The text is now much easier to read against the dark background, following WCAG AA standards while maintaining a professional security-focused aesthetic.
          </p>
          <div className="flex items-center gap-4 text-sm">
            <span style={{ color: 'var(--color-text-subtle)' }}>Last updated: Mar 11, 2027</span>
            <span style={{ color: 'var(--color-text-subtle)' }}>•</span>
            <span style={{ color: 'var(--color-text-subtle)' }}>Monthly Billing</span>
            <span style={{ color: 'var(--color-text-subtle)' }}>•</span>
            <span style={{ color: 'var(--color-accent)' }}>Pro Plan Active</span>
          </div>
        </div>
      </div>
    </div>
  );
}