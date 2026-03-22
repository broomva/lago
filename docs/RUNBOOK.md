# Lago Operations Runbook

## Deployment

### Railway Service
- **Project**: Life (Broomva Tech workspace)
- **Service**: lagod
- **Public URL**: `https://lago.broomva.tech`
- **Internal URL**: `lagod.railway.internal:8080`
- **Volume**: `/data/.lago` (journal.redb + blobs/)

### Deploy
```bash
# From ~/broomva/core/life/lago/
railway up --service lagod --ci -m "description"
```

### Environment Variables
| Variable | Source | Purpose |
|----------|--------|---------|
| `LAGO_JWT_SECRET` | Shared with broomva.tech `AUTH_SECRET` | JWT validation |
| `LAGO_DATA_DIR` | `/data/.lago` | Persistent storage |
| `RUST_LOG` | `info` | Log level |
| `PORT` | `8080` | HTTP port (Railway) |

### Health Checks
```bash
curl https://lago.broomva.tech/health          # Liveness
curl https://lago.broomva.tech/health/ready     # Readiness
curl https://lago.broomva.tech/metrics          # Prometheus
```

## Sessions

### Access Tiers
| Pattern | Tier | Anonymous Read | Authenticated Write | Admin Write |
|---------|------|---------------|-------------------|-------------|
| `site-assets:*` | Public | Yes | Yes | Yes |
| `site-content:*` | Public | Yes | Yes | Yes |
| `vault:*` | User | No | Owner only | Yes |
| `agent:*` | Agent | No | Owner only | Yes |
| Other | Default | Yes | Yes | Yes |

### Current Sessions
```bash
curl -s https://lago.broomva.tech/v1/sessions | python3 -m json.tool
```

## Content Management

### Sign admin JWT
```bash
JWT_SECRET="<from Railway>"
TOKEN=$(JWT_SECRET="$JWT_SECRET" bun -e "
import * as jose from 'jose';
const secret = new TextEncoder().encode(Bun.env.JWT_SECRET);
const jwt = await new jose.SignJWT({ sub: 'admin', email: 'admin@broomva.tech' })
  .setProtectedHeader({ alg: 'HS256' }).setIssuedAt().setExpirationTime('24h')
  .sign(secret);
console.log(jwt);
")
```

### Ingest site content
```bash
scripts/ingest-site-content.sh https://lago.broomva.tech
# Or with auth:
curl -X PUT https://lago.broomva.tech/v1/sessions/{sid}/files/{path} \
  -H "Authorization: Bearer $TOKEN" --data-binary @file.mdx
```

### Upload assets
```bash
scripts/asset-inventory.sh > scripts/asset-inventory.json
scripts/bulk-upload.sh https://lago.broomva.tech
```

## Snapshots
```bash
# Create
curl -X POST https://lago.broomva.tech/v1/sessions/{sid}/snapshots \
  -H "Content-Type: application/json" -d '{"name":"v1.0"}'

# List
curl https://lago.broomva.tech/v1/sessions/{sid}/snapshots

# Manifest at snapshot
curl https://lago.broomva.tech/v1/sessions/{sid}/snapshots/v1.0/manifest
```

## Diff
```bash
# Between snapshot and HEAD
curl "https://lago.broomva.tech/v1/sessions/{sid}/diff?from=snap:v1.0"

# Between two sequence numbers
curl "https://lago.broomva.tech/v1/sessions/{sid}/diff?from=5&to=20"
```

## Backup & Restore

### Manual Backup
```bash
# Via Railway shell or cron service
tar czf /tmp/lago-backup-$(date +%Y%m%d).tar.gz -C /data .lago/
# Upload to R2/S3
```

### Restore
```bash
# Stop lagod, restore data, restart
railway down --service lagod --yes
# ... restore data to volume ...
railway restart --service lagod --yes
```

## Troubleshooting

### Service won't start
```bash
railway logs --service lagod --lines 100
```

### 403 on write operations
- Check if session is public tier (site-assets:, site-content:)
- Anonymous writes to public sessions are denied
- Use JWT Bearer token for authenticated access

### 413 on large uploads
- Railway reverse proxy has body size limits (~2 MB)
- Use internal URL for large uploads: `lagod.railway.internal:8080`
- Or use `scripts/upload-large-assets.sh`

### Slow manifest queries
- Manifests are rebuilt from event replay on each request
- Create snapshots for frequently-accessed points
- Consider event compaction for sessions with many events
