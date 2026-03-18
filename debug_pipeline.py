"""Debug the pipeline/run 500 error."""
import requests, subprocess, time, os, sys, json, io

# Kill any existing process on port 8766
subprocess.run(['lsof', '-ti', ':8766'], capture_output=True)
result = subprocess.run(['lsof', '-ti', ':8766'], capture_output=True, text=True)
for pid in result.stdout.strip().split('\n'):
    if pid:
        subprocess.run(['kill', '-9', pid])
time.sleep(1)

env = os.environ.copy()
env['FIXOPS_API_TOKEN'] = 'test-token-e2e'
env['FIXOPS_DISABLE_TELEMETRY'] = '1'
env['PYTHONPATH'] = '.'

proc = subprocess.Popen(
    [sys.executable, '-m', 'uvicorn', 'apps.api.app:create_app', '--factory',
     '--host', '127.0.0.1', '--port', '8766', '--log-level', 'debug'],
    env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
)
time.sleep(8)

headers = {'X-API-Key': 'test-token-e2e'}

design_csv = "component,owner,criticality,notes\npayment-service,app-team,high,Handles card processing\n"
sbom = {'bomFormat': 'CycloneDX', 'specVersion': '1.4',
        'components': [{'type': 'library', 'name': 'test', 'version': '1.0.0'}]}
sarif = {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'test'}},
         'results': [{'ruleId': 'T1', 'level': 'error',
                      'message': {'text': 'test'}, 'locations': []}]}]}
cve = {'vulnerabilities': [{'cveID': 'CVE-2024-0001', 'title': 'test',
       'knownExploited': True, 'severity': 'high'}]}

# Upload design CSV first
buf = io.BytesIO(design_csv.encode())
r = requests.post(
    'http://127.0.0.1:8766/inputs/design',
    headers=headers,
    files={'file': ('design.csv', buf, 'text/csv')},
    timeout=10,
)
print(f'Upload design: {r.status_code}')

for name, data, ct in [('sbom', sbom, 'application/json'),
                        ('sarif', sarif, 'application/json'),
                        ('cve', cve, 'application/json')]:
    buf = io.BytesIO(json.dumps(data).encode())
    r = requests.post(
        f'http://127.0.0.1:8766/inputs/{name}',
        headers=headers,
        files={'file': (f'{name}.json', buf, ct)},
        timeout=10,
    )
    print(f'Upload {name}: {r.status_code}')

try:
    r = requests.post('http://127.0.0.1:8766/pipeline/run', headers=headers, timeout=120)
    print(f'Pipeline status: {r.status_code}')
    print(f'Pipeline body: {r.text[:5000]}')
except Exception as e:
    print(f'Pipeline request failed: {e}')

# Also get server logs
proc.terminate()
try:
    stdout, _ = proc.communicate(timeout=5)
    lines = stdout.decode(errors='replace').split('\n')
    # Print last 50 lines of server output
    print('\n=== SERVER LOGS (last 50 lines) ===')
    for line in lines[-50:]:
        print(line)
except Exception as e:
    print(f'Could not read server logs: {e}')

