const http = require('http');

function isFullSha(ref) {
  return typeof ref === 'string' && /^[0-9a-f]{40}$/.test(ref);
}

function evaluate(body) {
  body = body || {};
  const violations = [];

  const target = body.target;
  const event = body.event;
  const ref = body.ref;
  const workflow = body.workflow || {};
  const image = body.image || {};
  const permissions = workflow.permissions || {};
  const actions = Array.isArray(workflow.actions) ? workflow.actions : [];

  // 1. Permissions must be EXACTLY least privilege: no missing, no extra, no wrong values.
  const requiredPerms = { contents: 'read', packages: 'write', 'id-token': 'none' };
  const reqKeys = Object.keys(requiredPerms);
  const permKeys = Object.keys(permissions);
  const permsExact =
    permKeys.length === reqKeys.length &&
    reqKeys.every((k) => permissions[k] === requiredPerms[k]);
  if (!permsExact) violations.push('EXCESS_PERMISSION');

  // 2. PR trigger safety: pull_request_target is always unsafe.
  if (workflow.trigger === 'pull_request_target') {
    violations.push('UNSAFE_PR_TRIGGER');
  }

  // Tests must pass, matrix must be complete, failFast must be false.
  if (
    workflow.testsPassed !== true ||
    workflow.matrixComplete !== true ||
    workflow.failFast !== false
  ) {
    violations.push('TESTS_INCOMPLETE');
  }

  // 3. Action pinning: "actions"-owned actions may use a tag; everyone else needs a
  //    full 40-char lowercase hex commit SHA.
  let mutableActionFound = false;
  for (const a of actions) {
    if (!a) continue;
    if (a.owner === 'actions') continue;
    if (!isFullSha(a.ref)) {
      mutableActionFound = true;
    }
  }
  if (mutableActionFound) violations.push('MUTABLE_ACTION');

  // 4. Image hardening checks.
  if (image.multiStage !== true) violations.push('SINGLE_STAGE_IMAGE');
  if (image.runsAsRoot !== false) violations.push('ROOT_RUNTIME');
  if (!(image.secretMode === 'none' || image.secretMode === 'buildkit')) {
    violations.push('SECRET_IN_LAYER');
  }
  if (image.criticalVulnerabilities !== 0) violations.push('CRITICAL_CVE');
  if (image.digestPinned !== true) violations.push('UNPINNED_IMAGE');

  // 5. Production requires push to refs/heads/main + explicit environment approval.
  if (target === 'production') {
    const validRef = event === 'push' && ref === 'refs/heads/main';
    if (!validRef) violations.push('INVALID_PRODUCTION_REF');
    if (workflow.environmentApproval !== true) violations.push('APPROVAL_REQUIRED');
  }

  return {
    decision: violations.length === 0 ? 'promote' : 'block',
    violations,
  };
}

function requestHandler(req, res) {
  if (req.method === 'POST' && req.url === '/release-gate') {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
    });
    req.on('end', () => {
      let body;
      try {
        body = data ? JSON.parse(data) : {};
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON body' }));
        return;
      }
      const result = evaluate(body);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    });
    return;
  }

  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', endpoint: 'POST /release-gate' }));
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
}

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  http.createServer(requestHandler).listen(PORT, () => {
    console.log(`Release gate listening on port ${PORT}`);
  });
}

module.exports = { evaluate, requestHandler };
