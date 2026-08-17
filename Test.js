const assert = require('assert');
const { evaluate } = require('./server.js');

function basePayload(overrides = {}) {
  const base = {
    target: 'preview',
    event: 'pull_request',
    ref: 'refs/heads/feature/x',
    workflow: {
      trigger: 'pull_request',
      permissions: { contents: 'read', packages: 'write', 'id-token': 'none' },
      testsPassed: true,
      matrixComplete: true,
      failFast: false,
      actions: [
        { owner: 'actions', name: 'checkout', ref: 'v4' },
        {
          owner: 'docker',
          name: 'build-push-action',
          ref: 'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
        },
      ],
    },
    image: {
      multiStage: true,
      runsAsRoot: false,
      secretMode: 'buildkit',
      criticalVulnerabilities: 0,
      digestPinned: true,
    },
  };
  return deepMerge(base, overrides);
}

function deepMerge(target, src) {
  const out = Array.isArray(target) ? target.slice() : { ...target };
  for (const k of Object.keys(src)) {
    if (
      src[k] &&
      typeof src[k] === 'object' &&
      !Array.isArray(src[k]) &&
      target[k] &&
      typeof target[k] === 'object' &&
      !Array.isArray(target[k])
    ) {
      out[k] = deepMerge(target[k], src[k]);
    } else {
      out[k] = src[k];
    }
  }
  return out;
}

let passed = 0;
function check(name, actual, expectedViolations, expectedDecision) {
  const sortedActual = [...actual.violations].sort();
  const sortedExpected = [...expectedViolations].sort();
  assert.deepStrictEqual(sortedActual, sortedExpected, `${name}: violations mismatch. Got ${JSON.stringify(sortedActual)}`);
  assert.strictEqual(actual.decision, expectedDecision, `${name}: decision mismatch`);
  passed++;
  console.log(`PASS: ${name}`);
}

// 1. Fully compliant preview PR -> promote
check('safe preview PR', evaluate(basePayload()), [], 'promote');

// 2. Fully compliant production push -> promote
check(
  'safe production push',
  evaluate(
    basePayload({
      target: 'production',
      event: 'push',
      ref: 'refs/heads/main',
      workflow: { trigger: 'push', environmentApproval: true },
    })
  ),
  [],
  'promote'
);

// 3. Excess permission - extra scope
check(
  'excess permission extra scope',
  evaluate(
    basePayload({
      workflow: {
        permissions: { contents: 'read', packages: 'write', 'id-token': 'none', actions: 'write' },
      },
    })
  ),
  ['EXCESS_PERMISSION'],
  'block'
);

// 4. Excess permission - wrong value
check(
  'excess permission wrong value',
  evaluate(
    basePayload({
      workflow: { permissions: { contents: 'write', packages: 'write', 'id-token': 'none' } },
    })
  ),
  ['EXCESS_PERMISSION'],
  'block'
);

// 5. Unsafe PR trigger
check(
  'unsafe pr trigger',
  evaluate(basePayload({ workflow: { trigger: 'pull_request_target' } })),
  ['UNSAFE_PR_TRIGGER'],
  'block'
);

// 6. Tests incomplete - failFast true
check(
  'tests incomplete failFast',
  evaluate(basePayload({ workflow: { failFast: true } })),
  ['TESTS_INCOMPLETE'],
  'block'
);

// 7. Tests incomplete - matrix not complete
check(
  'tests incomplete matrix',
  evaluate(basePayload({ workflow: { matrixComplete: false } })),
  ['TESTS_INCOMPLETE'],
  'block'
);

// 8. Tests incomplete - tests not passed
check(
  'tests incomplete testsPassed',
  evaluate(basePayload({ workflow: { testsPassed: false } })),
  ['TESTS_INCOMPLETE'],
  'block'
);

// 9. Mutable third-party action (tag instead of SHA)
check(
  'mutable action tag',
  evaluate(
    basePayload({
      workflow: {
        actions: [
          { owner: 'actions', name: 'checkout', ref: 'v4' },
          { owner: 'docker', name: 'build-push-action', ref: 'v5' },
        ],
      },
    })
  ),
  ['MUTABLE_ACTION'],
  'block'
);

// 10. Mutable third-party action (uppercase hex, not lowercase) still invalid
check(
  'mutable action uppercase sha',
  evaluate(
    basePayload({
      workflow: {
        actions: [
          { owner: 'actions', name: 'checkout', ref: 'v4' },
          { owner: 'docker', name: 'build-push-action', ref: 'A1B2C3D4E5F60718293A4B5C6D7E8F9012345678' },
        ],
      },
    })
  ),
  ['MUTABLE_ACTION'],
  'block'
);

// 11. actions-owned action can keep a tag, third-party must be SHA - both ok
check(
  'actions owner tag ok, third party sha ok',
  evaluate(basePayload()),
  [],
  'promote'
);

// 12. Single stage image
check(
  'single stage image',
  evaluate(basePayload({ image: { multiStage: false } })),
  ['SINGLE_STAGE_IMAGE'],
  'block'
);

// 13. Root runtime
check('root runtime', evaluate(basePayload({ image: { runsAsRoot: true } })), ['ROOT_RUNTIME'], 'block');

// 14. Secret in layer - arg
check(
  'secret in layer arg',
  evaluate(basePayload({ image: { secretMode: 'arg' } })),
  ['SECRET_IN_LAYER'],
  'block'
);

// 15. Secret in layer - copy
check(
  'secret in layer copy',
  evaluate(basePayload({ image: { secretMode: 'copy' } })),
  ['SECRET_IN_LAYER'],
  'block'
);

// 16. secretMode none is fine
check('secret mode none ok', evaluate(basePayload({ image: { secretMode: 'none' } })), [], 'promote');

// 17. Critical CVE
check(
  'critical cve',
  evaluate(basePayload({ image: { criticalVulnerabilities: 2 } })),
  ['CRITICAL_CVE'],
  'block'
);

// 18. Unpinned image
check(
  'unpinned image',
  evaluate(basePayload({ image: { digestPinned: false } })),
  ['UNPINNED_IMAGE'],
  'block'
);

// 19. Production with wrong ref
check(
  'production invalid ref',
  evaluate(
    basePayload({
      target: 'production',
      event: 'push',
      ref: 'refs/heads/develop',
      workflow: { trigger: 'push', environmentApproval: true },
    })
  ),
  ['INVALID_PRODUCTION_REF'],
  'block'
);

// 20. Production with pull_request event instead of push
check(
  'production wrong event',
  evaluate(
    basePayload({
      target: 'production',
      event: 'pull_request',
      ref: 'refs/heads/main',
      workflow: { trigger: 'pull_request', environmentApproval: true },
    })
  ),
  ['INVALID_PRODUCTION_REF'],
  'block'
);

// 21. Production missing approval
check(
  'production missing approval',
  evaluate(
    basePayload({
      target: 'production',
      event: 'push',
      ref: 'refs/heads/main',
      workflow: { trigger: 'push' },
    })
  ),
  ['APPROVAL_REQUIRED'],
  'block'
);

// 22. Production: both ref invalid and approval missing
check(
  'production both invalid ref and no approval',
  evaluate(
    basePayload({
      target: 'production',
      event: 'pull_request',
      ref: 'refs/heads/feature/y',
      workflow: { trigger: 'pull_request' },
    })
  ),
  ['INVALID_PRODUCTION_REF', 'APPROVAL_REQUIRED'],
  'block'
);

// 23. Multi-failure combo: excess perms + unsafe trigger + mutable action + root + cve
check(
  'multi failure combo',
  evaluate(
    basePayload({
      workflow: {
        permissions: { contents: 'write', packages: 'write', 'id-token': 'none' },
        trigger: 'pull_request_target',
        actions: [
          { owner: 'actions', name: 'checkout', ref: 'v4' },
          { owner: 'someorg', name: 'someaction', ref: 'main' },
        ],
      },
      image: { runsAsRoot: true, criticalVulnerabilities: 5 },
    })
  ),
  ['EXCESS_PERMISSION', 'UNSAFE_PR_TRIGGER', 'MUTABLE_ACTION', 'ROOT_RUNTIME', 'CRITICAL_CVE'],
  'block'
);

// 24. Preview target ignores production-only rules even if ref/approval missing
check(
  'preview ignores production rules',
  evaluate(
    basePayload({
      target: 'preview',
      event: 'pull_request',
      ref: 'refs/heads/feature/z',
      workflow: { trigger: 'pull_request' }, // no environmentApproval field at all
    })
  ),
  [],
  'promote'
);

// 25. Missing id-token key entirely (undefined) -> excess/insufficient permission
check(
  'missing id-token key',
  evaluate(
    basePayload({
      workflow: { permissions: { contents: 'read', packages: 'write', 'id-token': undefined } },
    })
  ),
  ['EXCESS_PERMISSION'],
  'block'
);

console.log(`\n${passed} tests passed.`);
