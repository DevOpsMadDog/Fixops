import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

const errorRate = new Rate('errors');
const quoteDuration = new Trend('quote_duration');
const policyDuration = new Trend('policy_duration');
const requestCounter = new Counter('requests_total');

export const options = {
  stages: [
    { duration: '2m', target: 50 },   // Ramp up to 50 users
    { duration: '5m', target: 50 },   // Stay at 50 users
    { duration: '2m', target: 100 },  // Ramp up to 100 users
    { duration: '5m', target: 100 },  // Stay at 100 users
    { duration: '2m', target: 200 },  // Spike to 200 users
    { duration: '3m', target: 200 },  // Stay at 200 users
    { duration: '2m', target: 0 },    // Ramp down to 0 users
  ],
  thresholds: {
    'http_req_duration': ['p(95)<500', 'p(99)<1000'], // 95% of requests < 500ms, 99% < 1s
    'errors': ['rate<0.01'],                           // Error rate < 1%
    'http_req_failed': ['rate<0.01'],                  // Failed requests < 1%
    'quote_duration': ['p(95)<300'],                   // Quote creation < 300ms (p95)
    'policy_duration': ['p(95)<400'],                  // Policy creation < 400ms (p95)
  },
};

const BASE_URL = __ENV.BASE_URL || 'https://api.insurance.example.com/v1';
const JWT_TOKEN = __ENV.JWT_TOKEN || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';

const headers = {
  'Content-Type': 'application/json',
  'Authorization': `Bearer ${JWT_TOKEN}`,
};

function generateCustomerId() {
  return `cust_${Math.floor(Math.random() * 10000000000)}`;
}

function generateQuoteRequest() {
  const quoteTypes = ['auto', 'home', 'health', 'life'];
  const quoteType = quoteTypes[Math.floor(Math.random() * quoteTypes.length)];
  
  return {
    customer_id: generateCustomerId(),
    quote_type: quoteType,
    coverage_amount: Math.floor(Math.random() * 900000) + 100000,
    deductible: [500, 1000, 2500, 5000][Math.floor(Math.random() * 4)],
    vehicle: quoteType === 'auto' ? {
      year: 2020,
      make: 'Toyota',
      model: 'Camry',
      vin: '1HGBH41JXMN109186'
    } : undefined,
  };
}

export default function() {
  requestCounter.add(1);
  
  if (Math.random() < 0.7) {
    const quotePayload = JSON.stringify(generateQuoteRequest());
    const quoteStart = Date.now();
    
    const quoteResponse = http.post(
      `${BASE_URL}/quotes`,
      quotePayload,
      { headers }
    );
    
    const quoteDurationMs = Date.now() - quoteStart;
    quoteDuration.add(quoteDurationMs);
    
    const quoteSuccess = check(quoteResponse, {
      'quote status is 200': (r) => r.status === 200,
      'quote has quote_id': (r) => JSON.parse(r.body).quote_id !== undefined,
      'quote response time < 500ms': (r) => r.timings.duration < 500,
    });
    
    if (!quoteSuccess) {
      errorRate.add(1);
      console.error(`Quote creation failed: ${quoteResponse.status} - ${quoteResponse.body}`);
    }
    
    if (quoteSuccess && Math.random() < 0.2) {
      const quoteId = JSON.parse(quoteResponse.body).quote_id;
      
      const getQuoteResponse = http.get(
        `${BASE_URL}/quotes/${quoteId}`,
        { headers }
      );
      
      check(getQuoteResponse, {
        'get quote status is 200': (r) => r.status === 200,
        'get quote response time < 200ms': (r) => r.timings.duration < 200,
      });
    }
  }
  
  else if (Math.random() < 0.9) {
    const policyId = `pol_${Math.random().toString(36).substring(7)}`;
    
    const policyResponse = http.get(
      `${BASE_URL}/policies/${policyId}`,
      { headers }
    );
    
    check(policyResponse, {
      'policy status is 200 or 404': (r) => r.status === 200 || r.status === 404,
      'policy response time < 300ms': (r) => r.timings.duration < 300,
    });
  }
  
  else {
    const claimPayload = JSON.stringify({
      policy_id: `pol_${Math.random().toString(36).substring(7)}`,
      claim_type: 'accident',
      claim_amount: Math.floor(Math.random() * 50000) + 1000,
      description: 'Test claim submission for load testing',
    });
    
    const claimResponse = http.post(
      `${BASE_URL}/claims`,
      claimPayload,
      { headers }
    );
    
    check(claimResponse, {
      'claim status is 201 or 400': (r) => r.status === 201 || r.status === 400,
      'claim response time < 600ms': (r) => r.timings.duration < 600,
    });
  }
  
  sleep(Math.random() * 2 + 1); // 1-3 seconds
}

export function setup() {
  console.log('Starting baseline load test...');
  console.log(`Base URL: ${BASE_URL}`);
  console.log('Test duration: 21 minutes');
  console.log('Max concurrent users: 200');
  
  const healthCheck = http.get(`${BASE_URL.replace('/v1', '')}/health`);
  if (healthCheck.status !== 200) {
    throw new Error(`API health check failed: ${healthCheck.status}`);
  }
  
  return { startTime: new Date().toISOString() };
}

export function teardown(data) {
  console.log('Baseline load test completed');
  console.log(`Started at: ${data.startTime}`);
  console.log(`Ended at: ${new Date().toISOString()}`);
}

export function handleSummary(data) {
  return {
    'summary.json': JSON.stringify(data, null, 2),
    stdout: textSummary(data, { indent: ' ', enableColors: true }),
  };
}

function textSummary(data, options) {
  const indent = options.indent || '';
  const enableColors = options.enableColors || false;
  
  let summary = '\n' + indent + '=== Baseline Load Test Summary ===\n\n';
  
  summary += indent + 'Requests:\n';
  summary += indent + `  Total: ${data.metrics.requests_total.values.count}\n`;
  summary += indent + `  Failed: ${data.metrics.http_req_failed.values.rate * 100}%\n`;
  summary += indent + `  Error Rate: ${data.metrics.errors.values.rate * 100}%\n\n`;
  
  summary += indent + 'Response Times:\n';
  summary += indent + `  Avg: ${data.metrics.http_req_duration.values.avg.toFixed(2)}ms\n`;
  summary += indent + `  Min: ${data.metrics.http_req_duration.values.min.toFixed(2)}ms\n`;
  summary += indent + `  Max: ${data.metrics.http_req_duration.values.max.toFixed(2)}ms\n`;
  summary += indent + `  P95: ${data.metrics.http_req_duration.values['p(95)'].toFixed(2)}ms\n`;
  summary += indent + `  P99: ${data.metrics.http_req_duration.values['p(99)'].toFixed(2)}ms\n\n`;
  
  summary += indent + 'Quote Creation:\n';
  summary += indent + `  Avg: ${data.metrics.quote_duration.values.avg.toFixed(2)}ms\n`;
  summary += indent + `  P95: ${data.metrics.quote_duration.values['p(95)'].toFixed(2)}ms\n\n`;
  
  summary += indent + 'Policy Retrieval:\n';
  summary += indent + `  Avg: ${data.metrics.policy_duration.values.avg.toFixed(2)}ms\n`;
  summary += indent + `  P95: ${data.metrics.policy_duration.values['p(95)'].toFixed(2)}ms\n\n`;
  
  summary += indent + 'Thresholds:\n';
  for (const [name, threshold] of Object.entries(data.thresholds)) {
    const passed = threshold.ok ? '✓ PASS' : '✗ FAIL';
    summary += indent + `  ${name}: ${passed}\n`;
  }
  
  return summary;
}
