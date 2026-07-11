# Deploying aaliyah-core to Cloud Run

Everything in this directory is **repository-controlled and parameterized** — no
project id, secret, key, or connection string is committed. Secret *values* live
in Secret Manager and are resolved by Cloud Run at runtime.

## What's here
- `cloud-run-service.yaml` — Knative service manifest (template; `${VAR}` slots).
- `config.example.env` — every deploy variable; copy to `config.env` and fill in.
- `build-and-push.sh` — build the image (parent context) → Artifact Registry, SHA-tagged.
- `deploy.sh` — render + apply the manifest (`--validate` renders without any GCP call).
- `verify-deployment.sh` — post-deploy `/health` + `/ready` check with rollback hint.

## Migration strategy
Migrations run at boot (`server.ts` → `runMailMigrations`) inside a serialized,
idempotent, locked transaction before the socket opens. A new revision that
can't migrate fails its startup probe and receives no traffic — no half-migrated
serving state.

## Rollback strategy
Cloud Run keeps every revision. To roll back instantly:
```
gcloud run services update-traffic $SERVICE_NAME --region $REGION \
  --to-revisions PRIOR_REVISION=100
```
`verify-deployment.sh` prints this hint on failure. Because migrations are
additive/idempotent, traffic rollback is safe without a schema rollback.

---

## OWNER CHECKLIST — actions that require Andre's Google account / billing

These are the genuine external gates. None can be done from the repo. Run them
once; then `build-and-push.sh` + `deploy.sh` are self-service. Never paste secret
values into chat — put them straight into Secret Manager.

```bash
# 0. Auth + pick/create a project (BILLING approval is yours)
gcloud auth login
gcloud projects create YOUR_PROJECT --name="Aaliyah"        # or select an existing one
gcloud config set project YOUR_PROJECT
gcloud billing projects link YOUR_PROJECT --billing-account=YOUR_BILLING_ID

# 1. Enable APIs
gcloud services enable run.googleapis.com sqladmin.googleapis.com \
  secretmanager.googleapis.com cloudkms.googleapis.com \
  artifactregistry.googleapis.com

# 2. Artifact Registry
gcloud artifacts repositories create aaliyah --repository-format=docker \
  --location=us-central1

# 3. Cloud SQL (Postgres) — pick your own strong password (goes to Secret Manager, step 6)
gcloud sql instances create aaliyah-pg --database-version=POSTGRES_16 \
  --tier=db-custom-1-3840 --region=us-central1
gcloud sql databases create aaliyah --instance=aaliyah-pg
gcloud sql users create aaliyah --instance=aaliyah-pg --password=CHOOSE_A_STRONG_ONE

# 4. Cloud KMS (envelope encryption for stored refresh tokens)
gcloud kms keyrings create aaliyah --location=us-central1
gcloud kms keys create aaliyah-credentials --location=us-central1 \
  --keyring=aaliyah --purpose=encryption

# 5. Runtime service account + least-privilege IAM
gcloud iam service-accounts create aaliyah-core-run --display-name="Aaliyah Core Run"
SA=aaliyah-core-run@YOUR_PROJECT.iam.gserviceaccount.com
for ROLE in roles/cloudsql.client \
            roles/secretmanager.secretAccessor \
            roles/cloudkms.cryptoKeyEncrypterDecrypter \
            roles/logging.logWriter roles/monitoring.metricWriter; do
  gcloud projects add-iam-policy-binding YOUR_PROJECT --member="serviceAccount:$SA" --role="$ROLE"
done

# 6. Secrets (VALUES never go in the repo). AALIYAH_DATABASE_URL uses the Cloud
#    SQL unix socket: postgres://aaliyah:PASS@/aaliyah?host=/cloudsql/CONNECTION_NAME
printf 'postgres://aaliyah:PASS@/aaliyah?host=/cloudsql/YOUR_PROJECT:us-central1:aaliyah-pg' \
  | gcloud secrets create aaliyah-database-url --data-file=-
printf 'YOUR_GOOGLE_CLIENT_ID'     | gcloud secrets create aaliyah-google-client-id --data-file=-
printf 'YOUR_GOOGLE_CLIENT_SECRET' | gcloud secrets create aaliyah-google-client-secret --data-file=-

# 7. Register the Google apps (SEPARATE): OAuth consent screen + Gmail OAuth
#    client (redirect = GOOGLE_OAUTH_REDIRECT_URI). This is manual in the console.

# 8. Deploy
cp deploy/config.example.env deploy/config.env   # fill in real ids
deploy/build-and-push.sh                          # build + push, prints IMAGE=...
# set IMAGE=<pushed ref> in deploy/config.env
deploy/deploy.sh                                  # render + apply + verify
```

Until the project exists, `deploy/deploy.sh --validate` renders and fully
resolves the manifest locally with a filled `config.env` — proving the tooling
without any GCP call.
