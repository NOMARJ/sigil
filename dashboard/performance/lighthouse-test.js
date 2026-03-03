const lighthouse = require('lighthouse');
const chromeLauncher = require('chrome-launcher');
const fs = require('fs').promises;
const path = require('path');

// Performance budget configuration
const PERFORMANCE_BUDGET = {
  'first-contentful-paint': 1500,     // 1.5s
  'largest-contentful-paint': 2500,    // 2.5s (Core Web Vital)
  'first-meaningful-paint': 2000,      // 2s
  'speed-index': 2000,                 // 2s
  'total-blocking-time': 200,          // 200ms (related to FID)
  'max-potential-fid': 100,            // 100ms
  'cumulative-layout-shift': 0.1,      // CLS score (Core Web Vital)
  'time-to-interactive': 3000,         // 3s
  'server-response-time': 200,         // 200ms TTFB
  'bootup-time': 2000,                 // 2s JavaScript execution
  'mainthread-work-breakdown': 3000,   // 3s main thread work
  'dom-size': 1500,                    // Max DOM nodes
  'network-requests': 50,              // Max network requests
  'network-rtt': 50,                   // Round trip time
};

// Pages to test
const FORGE_PAGES = [
  { url: '/forge/tools', name: 'My Tools' },
  { url: '/forge/analytics', name: 'Analytics' },
  { url: '/forge/stacks', name: 'Tool Stacks' },
  { url: '/forge/monitoring', name: 'Monitoring' },
  { url: '/forge/settings', name: 'Settings' },
];

class ForgePerformanceTester {
  constructor(baseUrl = 'http://localhost:3000') {
    this.baseUrl = baseUrl;
    this.results = [];
    this.timestamp = new Date().toISOString();
  }

  async runLighthouse(url, opts = {}, config = null) {
    const chrome = await chromeLauncher.launch({ chromeFlags: ['--headless'] });
    opts.port = chrome.port;

    const defaultConfig = {
      extends: 'lighthouse:default',
      settings: {
        onlyCategories: ['performance'],
        throttling: {
          // Simulate 4G connection
          rttMs: 50,
          throughputKbps: 1638,
          cpuSlowdownMultiplier: 4,
        },
      },
    };

    try {
      const result = await lighthouse(url, opts, config || defaultConfig);
      await chrome.kill();
      return result.lhr;
    } catch (error) {
      await chrome.kill();
      throw error;
    }
  }

  analyzeMetrics(lhr, pageName) {
    const metrics = lhr.audits;
    const performanceScore = lhr.categories.performance.score * 100;

    const analysis = {
      page: pageName,
      url: lhr.finalUrl,
      performanceScore,
      coreWebVitals: {
        LCP: {
          value: metrics['largest-contentful-paint'].numericValue,
          score: metrics['largest-contentful-paint'].score,
          budget: PERFORMANCE_BUDGET['largest-contentful-paint'],
          passed: metrics['largest-contentful-paint'].numericValue <= PERFORMANCE_BUDGET['largest-contentful-paint'],
        },
        FID: {
          value: metrics['max-potential-fid']?.numericValue || 0,
          score: metrics['max-potential-fid']?.score || 1,
          budget: PERFORMANCE_BUDGET['max-potential-fid'],
          passed: (metrics['max-potential-fid']?.numericValue || 0) <= PERFORMANCE_BUDGET['max-potential-fid'],
        },
        CLS: {
          value: metrics['cumulative-layout-shift'].numericValue,
          score: metrics['cumulative-layout-shift'].score,
          budget: PERFORMANCE_BUDGET['cumulative-layout-shift'],
          passed: metrics['cumulative-layout-shift'].numericValue <= PERFORMANCE_BUDGET['cumulative-layout-shift'],
        },
      },
      metrics: {
        FCP: metrics['first-contentful-paint'].numericValue,
        FMP: metrics['first-meaningful-paint']?.numericValue || 0,
        SI: metrics['speed-index'].numericValue,
        TTI: metrics['interactive'].numericValue,
        TBT: metrics['total-blocking-time'].numericValue,
        TTFB: metrics['server-response-time']?.numericValue || 0,
      },
      resources: {
        totalRequests: metrics['network-requests']?.details?.items?.length || 0,
        totalSize: metrics['total-byte-weight']?.numericValue || 0,
        jsSize: metrics['unused-javascript']?.details?.overallSavingsBytes || 0,
        cssSize: metrics['unused-css-rules']?.details?.overallSavingsBytes || 0,
        imageSize: metrics['uses-optimized-images']?.details?.overallSavingsBytes || 0,
        domNodes: metrics['dom-size']?.numericValue || 0,
      },
      opportunities: this.extractOpportunities(metrics),
      diagnostics: this.extractDiagnostics(metrics),
    };

    return analysis;
  }

  extractOpportunities(metrics) {
    const opportunities = [];

    // Check for render-blocking resources
    if (metrics['render-blocking-resources']?.score < 1) {
      opportunities.push({
        title: 'Eliminate render-blocking resources',
        savings: metrics['render-blocking-resources'].details?.overallSavingsMs || 0,
        impact: 'high',
      });
    }

    // Check for unused JavaScript
    if (metrics['unused-javascript']?.score < 1) {
      opportunities.push({
        title: 'Remove unused JavaScript',
        savings: metrics['unused-javascript'].details?.overallSavingsMs || 0,
        size: metrics['unused-javascript'].details?.overallSavingsBytes || 0,
        impact: 'high',
      });
    }

    // Check for unused CSS
    if (metrics['unused-css-rules']?.score < 1) {
      opportunities.push({
        title: 'Remove unused CSS',
        savings: metrics['unused-css-rules'].details?.overallSavingsMs || 0,
        size: metrics['unused-css-rules'].details?.overallSavingsBytes || 0,
        impact: 'medium',
      });
    }

    // Check for image optimization
    if (metrics['uses-optimized-images']?.score < 1) {
      opportunities.push({
        title: 'Optimize images',
        savings: metrics['uses-optimized-images'].details?.overallSavingsMs || 0,
        size: metrics['uses-optimized-images'].details?.overallSavingsBytes || 0,
        impact: 'medium',
      });
    }

    // Check for efficient cache policy
    if (metrics['uses-long-cache-ttl']?.score < 1) {
      opportunities.push({
        title: 'Serve static assets with efficient cache policy',
        impact: 'low',
      });
    }

    return opportunities;
  }

  extractDiagnostics(metrics) {
    return {
      mainThreadWork: metrics['mainthread-work-breakdown']?.numericValue || 0,
      bootupTime: metrics['bootup-time']?.numericValue || 0,
      domSize: metrics['dom-size']?.numericValue || 0,
      criticalRequestChains: metrics['critical-request-chains']?.details?.chains || {},
      thirdPartyImpact: metrics['third-party-summary']?.details?.summary || {},
    };
  }

  async testAllPages() {
    console.log('Starting Forge Performance Testing with Lighthouse...\n');

    for (const page of FORGE_PAGES) {
      const url = `${this.baseUrl}${page.url}`;
      console.log(`Testing ${page.name}: ${url}`);

      try {
        const lhr = await this.runLighthouse(url);
        const analysis = this.analyzeMetrics(lhr, page.name);
        this.results.push(analysis);

        // Print summary
        console.log(`  Performance Score: ${analysis.performanceScore.toFixed(0)}/100`);
        console.log(`  LCP: ${analysis.coreWebVitals.LCP.value.toFixed(0)}ms (${analysis.coreWebVitals.LCP.passed ? '✓' : '✗'})`);
        console.log(`  FID: ${analysis.coreWebVitals.FID.value.toFixed(0)}ms (${analysis.coreWebVitals.FID.passed ? '✓' : '✗'})`);
        console.log(`  CLS: ${analysis.coreWebVitals.CLS.value.toFixed(3)} (${analysis.coreWebVitals.CLS.passed ? '✓' : '✗'})\n`);
      } catch (error) {
        console.error(`  Error testing ${page.name}: ${error.message}\n`);
        this.results.push({
          page: page.name,
          url,
          error: error.message,
        });
      }
    }

    return this.generateReport();
  }

  generateReport() {
    const summary = {
      timestamp: this.timestamp,
      baseUrl: this.baseUrl,
      pages: this.results,
      overall: {
        averageScore: this.results.reduce((sum, r) => sum + (r.performanceScore || 0), 0) / this.results.length,
        coreWebVitals: {
          LCP: {
            average: this.results.reduce((sum, r) => sum + (r.coreWebVitals?.LCP?.value || 0), 0) / this.results.length,
            passed: this.results.every(r => r.coreWebVitals?.LCP?.passed),
          },
          FID: {
            average: this.results.reduce((sum, r) => sum + (r.coreWebVitals?.FID?.value || 0), 0) / this.results.length,
            passed: this.results.every(r => r.coreWebVitals?.FID?.passed),
          },
          CLS: {
            average: this.results.reduce((sum, r) => sum + (r.coreWebVitals?.CLS?.value || 0), 0) / this.results.length,
            passed: this.results.every(r => r.coreWebVitals?.CLS?.passed),
          },
        },
        allPassed: this.results.every(r => 
          r.coreWebVitals?.LCP?.passed && 
          r.coreWebVitals?.FID?.passed && 
          r.coreWebVitals?.CLS?.passed
        ),
      },
      recommendations: this.generateRecommendations(),
    };

    return summary;
  }

  generateRecommendations() {
    const recommendations = [];

    // Analyze common issues across all pages
    const allOpportunities = this.results.flatMap(r => r.opportunities || []);
    const opportunityGroups = {};

    allOpportunities.forEach(opp => {
      if (!opportunityGroups[opp.title]) {
        opportunityGroups[opp.title] = {
          count: 0,
          totalSavings: 0,
          totalSize: 0,
        };
      }
      opportunityGroups[opp.title].count++;
      opportunityGroups[opp.title].totalSavings += opp.savings || 0;
      opportunityGroups[opp.title].totalSize += opp.size || 0;
    });

    // Generate prioritized recommendations
    Object.entries(opportunityGroups).forEach(([title, data]) => {
      if (data.count >= FORGE_PAGES.length * 0.5) { // Affects 50% or more pages
        recommendations.push({
          title,
          impact: 'high',
          affectedPages: data.count,
          potentialSavings: `${data.totalSavings.toFixed(0)}ms`,
          sizeReduction: data.totalSize ? `${(data.totalSize / 1024).toFixed(0)}KB` : null,
        });
      }
    });

    // Add specific recommendations based on metrics
    const avgLCP = this.results.reduce((sum, r) => sum + (r.coreWebVitals?.LCP?.value || 0), 0) / this.results.length;
    if (avgLCP > 2500) {
      recommendations.push({
        title: 'Optimize Largest Contentful Paint',
        impact: 'critical',
        description: 'LCP is above 2.5s threshold. Consider lazy loading, image optimization, and critical CSS inlining.',
      });
    }

    return recommendations;
  }

  async saveReport() {
    const report = this.generateReport();
    const reportPath = path.join(__dirname, 'lighthouse-report.json');
    await fs.writeFile(reportPath, JSON.stringify(report, null, 2));
    
    console.log('\n=== PERFORMANCE TEST SUMMARY ===');
    console.log(`Overall Performance Score: ${report.overall.averageScore.toFixed(0)}/100`);
    console.log(`Core Web Vitals: ${report.overall.allPassed ? 'PASSED ✓' : 'FAILED ✗'}`);
    console.log(`  LCP Average: ${report.overall.coreWebVitals.LCP.average.toFixed(0)}ms`);
    console.log(`  FID Average: ${report.overall.coreWebVitals.FID.average.toFixed(0)}ms`);
    console.log(`  CLS Average: ${report.overall.coreWebVitals.CLS.average.toFixed(3)}`);
    console.log(`\nReport saved to: ${reportPath}`);

    return report;
  }
}

// Run tests if executed directly
if (require.main === module) {
  const tester = new ForgePerformanceTester();
  tester.testAllPages()
    .then(() => tester.saveReport())
    .catch(console.error);
}

module.exports = ForgePerformanceTester;