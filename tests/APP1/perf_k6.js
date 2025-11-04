import http from 'k6/http';
import { check, sleep, Trend, Rate } from 'k6';

export let options = {
  scenarios: {
    baseline: { executor: 'ramping-vus', stages: [
      { duration: '1m', target: 50 },
      { duration: '3m', target: 150 },
      { duration: '1m', target: 0 }
    ] },
    spike: { executor: 'constant-arrival-rate', rate: 400, timeUnit: '1m', duration: '2m', preAllocatedVUs: 200, startTime: '5m' },
    soak: { executor: 'constant-vus', vus: 40, duration: '15m', startTime: '8m' }
  },
  thresholds: {
    http_req_duration: ['p(95)<500'],
    checks: ['rate>0.99']
  }
};

const errorRate = new Rate('errors');
const latencyTrend = new Trend('latency');

export default function () {
  const payload = JSON.stringify({
    customer_id: `user-${Math.floor(Math.random()*100000)}`,
    product_code: 'AUTO-PLUS',
    coverage_amount: 100000 + Math.random() * 50000
  });

  const headers = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${__ENV.BROKER_TOKEN || 'demo-token'}`
  };

  const res = http.post(`${__ENV.HOST}/api/quote`, payload, { headers });
  const ok = check(res, {
    'status is 200': (r) => r.status === 200,
    'latency < 450ms': (r) => r.timings.duration < 450
  });

  errorRate.add(!ok);
  latencyTrend.add(res.timings.duration);
  sleep(1);
}
