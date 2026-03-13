import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const pageLoadTime = new Trend('page_load_time');
const apiResponseTime = new Trend('api_response_time');
const errorRate = new Rate('errors');

// Test configuration
export const options = {
  stages: [
    { duration: '30s', target: 10 },   // Warm-up: ramp to 10 users
    { duration: '1m', target: 50 },    // Normal load: 50 concurrent users
    { duration: '2m', target: 100 },   // Peak load: 100 concurrent users
    { duration: '1m', target: 200 },   // Stress test: 200 users
    { duration: '30s', target: 0 },    // Cool-down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'],  // 95% of requests under 500ms
    'http_req_duration{type:page}': ['p(95)<2000'],  // Pages load under 2s
    'http_req_duration{type:api}': ['p(95)<200'],    // API calls under 200ms
    errors: ['rate<0.05'],                            // Error rate under 5%
    page_load_time: ['p(95)<2000'],                  // 95% page loads under 2s
    api_response_time: ['p(95)<300'],                // API responses under 300ms
  },
};

const BASE_URL = 'http://localhost:3000';

// Mock auth token (replace with actual token generation)
const AUTH_TOKEN = 'mock_jwt_token';

// Helper function to make authenticated requests
function makeAuthRequest(url, params = {}) {
  return http.get(url, {
    headers: {
      'Authorization': `Bearer ${AUTH_TOKEN}`,
      'Content-Type': 'application/json',
    },
    tags: { type: params.type || 'api' },
  });
}

export default function () {
  // Test 1: Load Forge Tools Page (Most Complex)
  const startTime = Date.now();
  
  // Load main page
  let res = http.get(`${BASE_URL}/forge/tools`, {
    tags: { type: 'page' },
  });
  
  check(res, {
    'Tools page loads successfully': (r) => r.status === 200,
    'Page loads under 2 seconds': (r) => r.timings.duration < 2000,
  });
  
  pageLoadTime.add(res.timings.duration);
  errorRate.add(res.status !== 200);

  sleep(1); // User think time

  // Test 2: API - Get Tracked Tools
  res = makeAuthRequest(`${BASE_URL}/api/forge/my-tools`);
  
  check(res, {
    'Get tracked tools success': (r) => r.status === 200,
    'API response under 200ms': (r) => r.timings.duration < 200,
    'Returns tools array': (r) => {
      const body = JSON.parse(r.body);
      return Array.isArray(body.tools);
    },
  });
  
  apiResponseTime.add(res.timings.duration);

  sleep(0.5);

  // Test 3: Track a New Tool
  const trackToolPayload = {
    tool_id: `tool-${Date.now()}`,
    name: `Performance Test Tool ${__VU}-${__ITER}`,
    repository_url: 'https://github.com/test/tool',
    ecosystem: 'mcp',
    description: 'Load testing tool',
    category: 'testing',
  };

  res = http.post(`${BASE_URL}/api/forge/my-tools/track`,
    JSON.stringify(trackToolPayload),
    {
      headers: {
        'Authorization': `Bearer ${AUTH_TOKEN}`,
        'Content-Type': 'application/json',
      },
      tags: { type: 'api' },
    }
  );

  check(res, {
    'Track tool success': (r) => r.status === 201 || r.status === 200,
    'Track operation under 300ms': (r) => r.timings.duration < 300,
  });

  apiResponseTime.add(res.timings.duration);
  errorRate.add(res.status >= 400);

  sleep(0.5);

  // Test 4: Load Analytics Page
  res = http.get(`${BASE_URL}/forge/analytics`, {
    tags: { type: 'page' },
  });
  
  check(res, {
    'Analytics page loads': (r) => r.status === 200,
    'Analytics under 2 seconds': (r) => r.timings.duration < 2000,
  });

  pageLoadTime.add(res.timings.duration);

  // Test 5: Get Analytics Data
  res = makeAuthRequest(`${BASE_URL}/api/forge/analytics/personal`);
  
  check(res, {
    'Analytics API success': (r) => r.status === 200,
    'Analytics data under 500ms': (r) => r.timings.duration < 500,
  });

  apiResponseTime.add(res.timings.duration);

  sleep(1);

  // Test 6: Search Tools (with pagination)
  const searchParams = new URLSearchParams({
    q: 'database',
    page: 1,
    limit: 20,
  });

  res = makeAuthRequest(`${BASE_URL}/api/forge/tools/search?${searchParams}`);
  
  check(res, {
    'Search API success': (r) => r.status === 200,
    'Search under 300ms': (r) => r.timings.duration < 300,
  });

  apiResponseTime.add(res.timings.duration);

  sleep(0.5);

  // Test 7: Concurrent Tool Operations
  const batch = [
    ['GET', `${BASE_URL}/api/forge/my-tools`],
    ['GET', `${BASE_URL}/api/forge/analytics/personal`],
    ['GET', `${BASE_URL}/api/forge/tools/recommended`],
  ];

  const responses = http.batch(batch.map(([method, url]) => ({
    method,
    url,
    params: {
      headers: {
        'Authorization': `Bearer ${AUTH_TOKEN}`,
      },
      tags: { type: 'api' },
    },
  })));

  responses.forEach((r) => {
    check(r, {
      'Batch request success': (r) => r.status === 200,
      'Batch under 500ms': (r) => r.timings.duration < 500,
    });
    apiResponseTime.add(r.timings.duration);
  });

  sleep(2); // User interaction delay
}

// Handle test summary
export function handleSummary(data) {
  const summary = {
    timestamp: new Date().toISOString(),
    total_requests: data.metrics.http_reqs.values.count,
    error_rate: data.metrics.errors.values.rate,
    page_load_p95: data.metrics.page_load_time ? data.metrics.page_load_time.values['p(95)'] : null,
    api_response_p95: data.metrics.api_response_time ? data.metrics.api_response_time.values['p(95)'] : null,
    http_req_duration_p95: data.metrics.http_req_duration.values['p(95)'],
    http_req_duration_p99: data.metrics.http_req_duration.values['p(99)'],
    checks_passed: data.metrics.checks.values.passes,
    checks_failed: data.metrics.checks.values.fails,
    vus_max: data.metrics.vus_max.values.value,
  };

  // Performance thresholds
  const passed = summary.page_load_p95 < 2000 && 
                 summary.api_response_p95 < 300 && 
                 summary.error_rate < 0.05;

  console.log('\n=== FORGE PERFORMANCE TEST RESULTS ===\n');
  console.log(`Status: ${passed ? 'PASSED ✓' : 'FAILED ✗'}`);
  console.log(`Total Requests: ${summary.total_requests}`);
  console.log(`Error Rate: ${(summary.error_rate * 100).toFixed(2)}%`);
  console.log(`Page Load Time (p95): ${summary.page_load_p95?.toFixed(0)}ms`);
  console.log(`API Response Time (p95): ${summary.api_response_p95?.toFixed(0)}ms`);
  console.log(`HTTP Duration (p95): ${summary.http_req_duration_p95.toFixed(0)}ms`);
  console.log(`HTTP Duration (p99): ${summary.http_req_duration_p99.toFixed(0)}ms`);
  console.log(`Max Concurrent Users: ${summary.vus_max}`);
  console.log(`Checks: ${summary.checks_passed} passed, ${summary.checks_failed} failed`);

  return {
    'stdout': JSON.stringify(summary, null, 2),
    '/Users/reecefrazier/CascadeProjects/sigil/dashboard/performance/results.json': JSON.stringify(summary, null, 2),
  };
}