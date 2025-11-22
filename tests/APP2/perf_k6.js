import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '1m', target: 40 },
    { duration: '4m', target: 160 },
    { duration: '2m', target: 300 },
    { duration: '1m', target: 50 }
  ],
  thresholds: {
    http_req_failed: ['rate<0.02'],
    http_req_duration: ['p(95)<450']
  }
};

export default function() {
  const payload = JSON.stringify({
    id: 'offerFeed',
    variables: {
      partnerId: 'PART-202',
      locale: 'en-US'
    }
  });

  const res = http.post(`${__ENV.HOST}/graphql`, payload, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${__ENV.VIEWER_TOKEN || 'token'}`
    }
  });

  check(res, {
    'status 200 or 429': (r) => r.status === 200 || r.status === 429,
    'response under 420ms': (r) => r.timings.duration < 420
  });

  sleep(0.5);
}
