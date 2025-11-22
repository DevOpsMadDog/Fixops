import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  scenarios: {
    baseline: { executor: 'constant-vus', vus: 50, duration: '10m' },
    surge: { executor: 'ramping-arrival-rate', startRate: 100, timeUnit: '1m', preAllocatedVUs: 200, stages: [
      { target: 400, duration: '3m' },
      { target: 100, duration: '2m' }
    ], startTime: '10m' }
  },
  thresholds: {
    http_req_duration: ['p(95)<480'],
    http_req_failed: ['rate<0.01']
  }
};

export default function () {
  const query = Math.random() > 0.7 ? 'name=Smith' : 'birthdate=1980-01-01';
  const res = http.get(`${__ENV.HOST}/fhir/Patient?${query}`, {
    headers: { Authorization: `Bearer ${__ENV.CLINICIAN_TOKEN || 'token'}` }
  });
  check(res, {
    'status 200 or 400': (r) => r.status === 200 || r.status === 400,
    'duration < 460ms': (r) => r.timings.duration < 460
  });
  sleep(0.5);
}
