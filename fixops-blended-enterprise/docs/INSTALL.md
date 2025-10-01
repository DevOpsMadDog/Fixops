# FixOps Enterprise – Customer Install Guide (Cloud/Kubernetes)

This guide describes how to deploy FixOps on your cloud Kubernetes cluster with no app‑level authentication (infra‑layer access only), optional HA, and persistent storage.

## 1. Prerequisites
- Kubernetes v1.24+
- Ingress controller (NGINX, ALB, etc.)
- DNS entry pointing to your ingress
- MongoDB (managed or self‑hosted). Provide connection string via MONGO_URL
- Optional: Prometheus/Grafana for metrics
- Optional: Backstage instance

## 2. Architecture
- Frontend (React) served at / (port 3000 via service; ingress routes non‑/api traffic)
- Backend (FastAPI) at /api/* (ingress routes /api → internal service at 0.0.0.0:8001)
- MongoDB is external to the cluster and referenced via MONGO_URL
- Persistent volume for uploads: /app/data/uploads

## 3. Environment variables
Backend
- MONGO_URL: MongoDB connection string
- SECRET_KEY: random string
- EMERGENT_LLM_KEY (or provider keys): used by Enhanced multi‑LLM
- ENABLED_EPSS=false, ENABLED_KEV=false, ENABLED_VEX=false, ENABLED_RSS_SIDECAR=false (feature flags)

Frontend
- REACT_APP_BACKEND_URL: external URL to your backend ingress root (e.g., https://fixops.example.com)

Notes
- Do not hardcode URLs in code. Frontend must use REACT_APP_BACKEND_URL and prefix /api for backend routes.
- Backend binds to 0.0.0.0:8001 and must not be changed.

## 4. Kubernetes deployment
- Apply provided manifests in kubernetes/ (deployment.yaml, service.yaml, ingress as applicable)
- Create a PersistentVolumeClaim for uploads (example):

```
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: fixops-uploads-pvc
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

- Mount PVC in backend deployment:
```
        volumeMounts:
        - name: uploads
          mountPath: /app/data/uploads
      volumes:
      - name: uploads
        persistentVolumeClaim:
          claimName: fixops-uploads-pvc
```

### Optional HA
- Increase replicas for frontend and backend to >=2
- Add HorizontalPodAutoscaler (CPU or request duration)
- Add PodDisruptionBudget:
```
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: fixops-backend-pdb
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: fixops-backend
```
- Anti‑affinity to spread pods across nodes

## 5. Backstage integration
- Use backstage/catalog-info.yaml to register FixOps components and provide quick links:
  - Enhanced Analysis POST /api/v1/enhanced/analysis
  - Upload scans endpoints

## 6. Observability
- Enable Prometheus scraping of /metrics on backend service
- Ship logs to your logging stack (stdout from pods)

## 7. Security model
- No app‑level auth (as requested). Restrict access using:
  - Ingress allowlists, private networking, or WAF
  - NetworkPolicies for DB egress
  - Kubernetes Secrets for keys

## 8. Smoke test
- Open / to load UI
- Call GET /api/v1/enhanced/capabilities
- POST /api/v1/enhanced/compare-llms with a small JSON body
- Try chunked upload init/chunk/complete

## 9. Rollback strategy
- Use your GitOps pipeline to rollback to last known good image
- PVC retains uploads; ensure backups for Mongo

## 10. Support
- See docs/REQUIREMENTS.md for functional/non‑functional requirements, and docs/SSVC.md for decision methodology.
