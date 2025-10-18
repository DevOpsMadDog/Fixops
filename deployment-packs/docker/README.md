# FixOps Docker Deployment Pack

Production-ready Docker Compose configuration for deploying FixOps Decision Engine.

## Features

- **Multi-container architecture**: Backend, MongoDB, Redis, Frontend (optional)
- **Health checks**: All services include health monitoring
- **Resource limits**: CPU and memory constraints for production
- **Persistent storage**: Data volumes for MongoDB, Redis, and Evidence Lake
- **Optional components**: Frontend UI, Nginx reverse proxy, Prometheus/Grafana monitoring
- **Environment-based configuration**: Easy customization via .env file

## Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- At least 4GB RAM available
- 20GB disk space for data volumes

## Quick Start

### 1. Configure Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your configuration
nano .env
```

**Required variables:**
- `MONGO_PASSWORD`: Secure MongoDB password
- `REDIS_PASSWORD`: Secure Redis password
- `SECRET_KEY`: Random secret key (generate with `openssl rand -hex 32`)
- `EMERGENT_LLM_KEY`: Your Emergent LLM API key

### 2. Deploy FixOps

```bash
# Start core services (backend, MongoDB, Redis)
docker-compose up -d

# Or start with frontend
docker-compose --profile frontend up -d

# Or start with all optional services
docker-compose --profile frontend --profile nginx --profile monitoring up -d
```

### 3. Verify Deployment

```bash
# Check service status
docker-compose ps

# View logs
docker-compose logs -f fixops-backend

# Test API health
curl http://localhost:8001/health
```

## Service Profiles

### Core Services (Always Running)
- **fixops-backend**: Main API service (port 8001)
- **mongodb**: Evidence Lake database (port 27017)
- **redis**: Caching layer (port 6379)

### Optional Profiles

#### Frontend Profile
```bash
docker-compose --profile frontend up -d
```
- **fixops-frontend**: React UI (port 3000)

#### Nginx Profile
```bash
docker-compose --profile nginx up -d
```
- **nginx**: Reverse proxy (ports 80, 443)

#### Monitoring Profile
```bash
docker-compose --profile monitoring up -d
```
- **prometheus**: Metrics collection (port 9090)
- **grafana**: Dashboards (port 3001)

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `ENVIRONMENT` | Deployment environment | production | No |
| `DEMO_MODE` | Use demo data | false | No |
| `MONGO_PASSWORD` | MongoDB password | - | Yes |
| `REDIS_PASSWORD` | Redis password | - | Yes |
| `SECRET_KEY` | Application secret | - | Yes |
| `EMERGENT_LLM_KEY` | LLM API key | - | Yes |
| `BACKEND_PORT` | Backend port | 8001 | No |
| `WORKERS` | Uvicorn workers | 4 | No |

### Volumes

Persistent data is stored in Docker volumes:
- `mongodb_data`: MongoDB database
- `redis_data`: Redis cache
- `evidence_data`: Evidence Lake artifacts
- `uploads_data`: Temporary uploads

### Resource Limits

Default resource allocations:
- **Backend**: 2 CPU, 2GB RAM
- **MongoDB**: 1 CPU, 1GB RAM
- **Redis**: 0.5 CPU, 256MB RAM
- **Frontend**: 0.5 CPU, 512MB RAM

Adjust in `docker-compose.yml` under `deploy.resources`.

## Operations

### Scaling

```bash
# Scale backend replicas
docker-compose up -d --scale fixops-backend=3
```

### Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f fixops-backend

# Last 100 lines
docker-compose logs --tail=100 fixops-backend
```

### Backup

```bash
# Backup MongoDB
docker-compose exec mongodb mongodump --out /data/backup

# Backup volumes
docker run --rm -v fixops_mongodb_data:/data -v $(pwd):/backup alpine tar czf /backup/mongodb-backup.tar.gz /data
```

### Updates

```bash
# Pull latest images
docker-compose pull

# Restart services
docker-compose up -d
```

### Cleanup

```bash
# Stop services
docker-compose down

# Remove volumes (WARNING: deletes all data)
docker-compose down -v
```

## Monitoring

### Prometheus Metrics

Access Prometheus at http://localhost:9090

Available metrics:
- `fixops_http_requests_total`
- `fixops_decision_latency_seconds`
- `fixops_evidence_lake_size_bytes`

### Grafana Dashboards

Access Grafana at http://localhost:3001

Default credentials:
- Username: `admin`
- Password: Set in `GRAFANA_PASSWORD` env var

## Security

### Production Checklist

- [ ] Change all default passwords
- [ ] Generate strong `SECRET_KEY`
- [ ] Configure SSL/TLS certificates for Nginx
- [ ] Enable authentication (`AUTH_DISABLED=false`)
- [ ] Restrict network access with firewall rules
- [ ] Regular backups of volumes
- [ ] Monitor logs for security events
- [ ] Keep Docker images updated

### SSL/TLS Configuration

1. Place certificates in `nginx/ssl/`:
   - `cert.pem`: SSL certificate
   - `key.pem`: Private key

2. Uncomment HTTPS server block in `nginx/nginx.conf`

3. Restart Nginx:
   ```bash
   docker-compose restart nginx
   ```

## Troubleshooting

### Backend Won't Start

```bash
# Check logs
docker-compose logs fixops-backend

# Verify MongoDB connection
docker-compose exec fixops-backend env | grep MONGO_URL
```

### Database Connection Issues

```bash
# Test MongoDB connectivity
docker-compose exec mongodb mongosh -u fixops -p $MONGO_PASSWORD

# Check Redis
docker-compose exec redis redis-cli -a $REDIS_PASSWORD ping
```

### High Memory Usage

```bash
# Check resource usage
docker stats

# Reduce worker count
# Edit .env: WORKERS=2
docker-compose up -d
```

## Integration with CI/CD

### Example GitLab CI

```yaml
deploy:
  stage: deploy
  script:
    - docker-compose pull
    - docker-compose up -d
  only:
    - main
```

### Example GitHub Actions

```yaml
- name: Deploy FixOps
  run: |
    docker-compose pull
    docker-compose up -d
```

## Support

For issues and questions:
- GitHub: https://github.com/DevOpsMadDog/Fixops
- Documentation: https://github.com/DevOpsMadDog/Fixops/tree/main/docs
