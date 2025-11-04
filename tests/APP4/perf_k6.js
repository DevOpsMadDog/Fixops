import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '2m', target: 60 },
    { duration: '5m', target: 250 },
    { duration: '2m', target: 400 },
    { duration: '2m', target: 80 }
  ],
  thresholds: {
    http_req_duration: ['p(95)<420'],
    http_req_failed: ['rate<0.01']
  }
};

export default function() {
  const payload = JSON.stringify({
    store_id: 'STORE-' + Math.floor(Math.random()*1000),
    amount: Math.round(Math.random()*20000)/100,
    currency: 'USD',
    payment_token: 'tok_' + Math.random().toString(36).substring(2,8),
    device_attestation: 'att-' + Math.random().toString(36).substring(2,10)
  });
  const headers = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${__ENV.DEVICE_TOKEN || 'token'}`,
    'Idempotency-Key': `key-${__VU}-${__ITER}`
  };
  const res = http.post(`${__ENV.HOST}/checkout`, payload, { headers });
  check(res, {
    'status 201 or 200': (r) => r.status === 201 || r.status === 200,
    'duration < 400ms': (r) => r.timings.duration < 400
  });
  sleep(0.4);
}
