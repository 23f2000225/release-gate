# Release Gate

A deterministic policy endpoint that decides whether a GitHub Actions run may
promote a container image, combining least-privilege permissions, complete
matrix testing, action pinning, and hardened-image checks.

## Endpoint

`POST /release-gate`

Request body: see the shape described in the task. Response:

```json
{"decision": "promote | block", "violations": ["CODE", "..."]}
```

`decision` is `"promote"` only when `violations` is empty.

## Rules implemented (server.js -> evaluate)

1. **EXCESS_PERMISSION** — `workflow.permissions` must be *exactly*
   `{"contents":"read","packages":"write","id-token":"none"}`. Any missing
   key, wrong value, or extra key trips this.
2. **UNSAFE_PR_TRIGGER** — `workflow.trigger` must never be
   `pull_request_target`.
3. **TESTS_INCOMPLETE** — `testsPassed` must be `true`, `matrixComplete` must
   be `true`, and `failFast` must be `false`.
4. **MUTABLE_ACTION** — actions with `owner === "actions"` may use a version
   tag. Every other action must be pinned to a full 40-character lowercase
   hex commit SHA (`^[0-9a-f]{40}$`).
5. Image hardening:
   - **SINGLE_STAGE_IMAGE** if `image.multiStage !== true`
   - **ROOT_RUNTIME** if `image.runsAsRoot !== false`
   - **SECRET_IN_LAYER** if `image.secretMode` is not `"none"` or `"buildkit"`
   - **CRITICAL_CVE** if `image.criticalVulnerabilities !== 0`
   - **UNPINNED_IMAGE** if `image.digestPinned !== true`
6. Production (`target === "production"`) additionally requires:
   - **INVALID_PRODUCTION_REF** unless `event === "push"` and
     `ref === "refs/heads/main"`
   - **APPROVAL_REQUIRED** unless `workflow.environmentApproval === true`

All applicable codes are returned together (order doesn't matter).

## Run locally

```bash
npm start          # starts the HTTP server on :3000
npm test           # runs the deterministic test suite (25 cases)
```

Example call:

```bash
curl -X POST http://localhost:3000/release-gate \
  -H "Content-Type: application/json" \
  -d '{
    "target": "preview",
    "event": "pull_request",
    "ref": "refs/heads/feature/x",
    "workflow": {
      "trigger": "pull_request",
      "permissions": {"contents":"read","packages":"write","id-token":"none"},
      "testsPassed": true, "matrixComplete": true, "failFast": false,
      "actions": [{"owner":"actions","name":"checkout","ref":"v4"}]
    },
    "image": {
      "multiStage": true, "runsAsRoot": false, "secretMode": "none",
      "criticalVulnerabilities": 0, "digestPinned": true
    }
  }'
```

## Deployment

Deploy `server.js` (no external dependencies — pure Node `http`) to any
Node-capable host, e.g.:

- **Render** — New Web Service → connect this repo → Build: `npm install` →
  Start: `npm start`.
- **Railway** — New Project → Deploy from GitHub repo → it auto-detects
  `npm start`.
- **Fly.io** — `fly launch`, then `fly deploy` (a `Procfile`/`Dockerfile`
  isn't required if you use the Node buildpack).

Whichever host you use, the public base URL + `/release-gate` is the
endpoint to submit.

## GitHub Actions evidence

`.github/workflows/tds-ga7-release-gate.yml` is named **TDS GA7 Release
Gate**, runs on push to `main`, includes a step named exactly
`TDS identity: 23f2000225@ds.study.iitm.ac.in`, and runs `node test.js`
against this implementation.
