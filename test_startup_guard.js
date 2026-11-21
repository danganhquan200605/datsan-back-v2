/**
 * DATSANONLINE — TEST SUITE: STARTUP ENVIRONMENT GUARD
 * 
 * Tests:
 * 1. Valid Staging configuration in Local/Dev mode
 * 2. Hard block when Production Project Ref (ckrmfyuymuvaiymfxvhj) is in SUPABASE_URL
 * 3. Hard block when Production Ref is in DATABASE_URL (direct URI)
 * 4. Hard block when Production Ref is in DATABASE_URL (pooler URI)
 * 5. Hard block when Production Ref is in arbitrary env variables
 * 6. Hard block when Production Ref is in JWT token payload
 * 7. Hard block when Staging SUPABASE_URL is missing (no fallback)
 * 8. Hard block when Staging API keys are missing
 * 9. Hard block when foreign unapproved Project Ref is supplied
 * 10. Authorization in Production Render environment (RENDER=true)
 * 11. Process integration test: verifying node index.js exits with code 1 when given Production Ref
 * 12. Process integration test: verifying node index.js exits with code 1 when missing config
 */

const {
  STAGING_PROJECT_REF,
  PRODUCTION_PROJECT_REF,
  validateEnvironmentConfig,
  enforceStartupEnvironmentGuard,
  extractProjectRefFromUrl,
  extractRefFromJwt,
  isProductionRender
} = require('./envGuard');
const { spawnSync } = require('child_process');
const path = require('path');

let passCount = 0;
let failCount = 0;

function assert(condition, message) {
  if (condition) {
    passCount++;
    console.log(`  ✅ PASS: ${message}`);
  } else {
    failCount++;
    console.error(`  ❌ FAIL: ${message}`);
  }
}

console.log('========================================================================');
console.log('DATSANONLINE — STARTUP ENVIRONMENT GUARD VERIFICATION SUITE');
console.log('========================================================================\n');

// Mock Staging JWT & Production JWT tokens for testing
function makeMockJwt(projectRef) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
  const payload = Buffer.from(JSON.stringify({ iss: 'supabase', ref: projectRef, role: 'anon' })).toString('base64');
  const sig = 'mock_signature_for_testing';
  return `${header}.${payload}.${sig}`;
}

const stagingAnonKey = makeMockJwt(STAGING_PROJECT_REF);
const prodAnonKey = makeMockJwt(PRODUCTION_PROJECT_REF);

// --------------------------------------------------------------------------
// 1. UNIT TESTS: URL & JWT PARSING
// --------------------------------------------------------------------------
console.log('--- 1. URL & JWT REF EXTRACTION ---');

assert(
  extractProjectRefFromUrl('https://fllbhjovifmzyfjubifx.supabase.co') === STAGING_PROJECT_REF,
  'Extract project ref from Supabase HTTPS URL'
);

assert(
  extractProjectRefFromUrl('postgresql://postgres:pass@db.fllbhjovifmzyfjubifx.supabase.co:5432/postgres') === STAGING_PROJECT_REF,
  'Extract project ref from direct PostgreSQL URL'
);

assert(
  extractProjectRefFromUrl('postgresql://postgres.ckrmfyuymuvaiymfxvhj:secret@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres') === PRODUCTION_PROJECT_REF,
  'Extract project ref from Supabase Pooler URI'
);

assert(
  extractRefFromJwt(stagingAnonKey) === STAGING_PROJECT_REF,
  'Extract ref claim from Staging JWT token'
);

assert(
  extractRefFromJwt(prodAnonKey) === PRODUCTION_PROJECT_REF,
  'Extract ref claim from Production JWT token'
);

// --------------------------------------------------------------------------
// 2. UNIT TESTS: VALID STAGING CONFIGURATION
// --------------------------------------------------------------------------
console.log('\n--- 2. VALID STAGING CONFIGURATION (LOCAL/DEV) ---');

const validStagingEnv = {
  SUPABASE_URL: `https://${STAGING_PROJECT_REF}.supabase.co`,
  SUPABASE_ANON_KEY: stagingAnonKey,
  DATABASE_URL: `postgresql://postgres:pass@db.${STAGING_PROJECT_REF}.supabase.co:5432/postgres`
};

const stagingRes = validateEnvironmentConfig(validStagingEnv);
assert(stagingRes.ok === true, 'Staging configuration is accepted');
assert(stagingRes.mode === 'LOCAL_DEV', 'Correctly identified mode as LOCAL_DEV');
assert(stagingRes.stagingRef === STAGING_PROJECT_REF, 'Correctly matched Staging ref');

// Also test enforceStartupEnvironmentGuard does not throw for valid staging
try {
  const enforced = enforceStartupEnvironmentGuard({ env: validStagingEnv, exitOnError: false });
  assert(enforced.ok === true, 'enforceStartupEnvironmentGuard passes for valid Staging');
} catch (e) {
  assert(false, `enforceStartupEnvironmentGuard threw unexpectedly: ${e.message}`);
}

// --------------------------------------------------------------------------
// 3. UNIT TESTS: PRODUCTION REF HARD BLOCK
// --------------------------------------------------------------------------
console.log('\n--- 3. PRODUCTION REF (ckrmfyuymuvaiymfxvhj) HARD BLOCK ---');

// 3a. Production SUPABASE_URL
const prodUrlEnv = {
  SUPABASE_URL: `https://${PRODUCTION_PROJECT_REF}.supabase.co`,
  SUPABASE_ANON_KEY: stagingAnonKey
};
const prodUrlRes = validateEnvironmentConfig(prodUrlEnv);
assert(prodUrlRes.ok === false, 'Blocked when SUPABASE_URL points to Production');
assert(prodUrlRes.code === 'ERR_PRODUCTION_REF_BLOCKED', 'Error code is ERR_PRODUCTION_REF_BLOCKED');

// 3b. Production direct DATABASE_URL
const prodDbEnv = {
  SUPABASE_URL: `https://${STAGING_PROJECT_REF}.supabase.co`,
  SUPABASE_ANON_KEY: stagingAnonKey,
  DATABASE_URL: `postgresql://postgres:secret@db.${PRODUCTION_PROJECT_REF}.supabase.co:5432/postgres`
};
const prodDbRes = validateEnvironmentConfig(prodDbEnv);
assert(prodDbRes.ok === false, 'Blocked when direct DATABASE_URL points to Production');
assert(prodDbRes.code === 'ERR_PRODUCTION_REF_BLOCKED', 'Direct DB error code is ERR_PRODUCTION_REF_BLOCKED');

// 3c. Production pooler DATABASE_URL
const prodPoolerEnv = {
  SUPABASE_URL: `https://${STAGING_PROJECT_REF}.supabase.co`,
  SUPABASE_ANON_KEY: stagingAnonKey,
  DATABASE_URL: `postgresql://postgres.${PRODUCTION_PROJECT_REF}:secret@aws-1-ap-northeast-2.pooler.supabase.com:5432/postgres`
};
const prodPoolerRes = validateEnvironmentConfig(prodPoolerEnv);
assert(prodPoolerRes.ok === false, 'Blocked when pooler DATABASE_URL points to Production');
assert(prodPoolerRes.code === 'ERR_PRODUCTION_REF_BLOCKED', 'Pooler DB error code is ERR_PRODUCTION_REF_BLOCKED');

// 3d. Production JWT token
const prodJwtEnv = {
  SUPABASE_URL: `https://${STAGING_PROJECT_REF}.supabase.co`,
  SUPABASE_ANON_KEY: prodAnonKey
};
const prodJwtRes = validateEnvironmentConfig(prodJwtEnv);
assert(prodJwtRes.ok === false, 'Blocked when API key JWT belongs to Production');
assert(prodJwtRes.code === 'ERR_PRODUCTION_REF_BLOCKED', 'JWT error code is ERR_PRODUCTION_REF_BLOCKED');

// 3e. Production Ref in arbitrary env var
const prodArbitraryEnv = {
  SUPABASE_URL: `https://${STAGING_PROJECT_REF}.supabase.co`,
  SUPABASE_ANON_KEY: stagingAnonKey,
  ARBITRARY_VAR: `some-config-with-${PRODUCTION_PROJECT_REF}-inside`
};
const prodArbitraryRes = validateEnvironmentConfig(prodArbitraryEnv);
assert(prodArbitraryRes.ok === false, 'Blocked when Production Ref is found in arbitrary env var');
assert(prodArbitraryRes.code === 'ERR_PRODUCTION_REF_BLOCKED', 'Arbitrary env var error code is ERR_PRODUCTION_REF_BLOCKED');

// Verify enforceStartupEnvironmentGuard throws with ERR_PRODUCTION_REF_BLOCKED
try {
  enforceStartupEnvironmentGuard({ env: prodUrlEnv, exitOnError: false });
  assert(false, 'Should have thrown for Production URL');
} catch (err) {
  assert(err.code === 'ERR_PRODUCTION_REF_BLOCKED', 'enforceStartupEnvironmentGuard threw ERR_PRODUCTION_REF_BLOCKED');
}

// --------------------------------------------------------------------------
// 4. UNIT TESTS: MISSING STAGING CONFIGURATION (ZERO FALLBACK)
// --------------------------------------------------------------------------
console.log('\n--- 4. MISSING STAGING CONFIGURATION (NO FALLBACK) ---');

// 4a. Missing SUPABASE_URL
const missingUrlEnv = {
  SUPABASE_ANON_KEY: stagingAnonKey
};
const missingUrlRes = validateEnvironmentConfig(missingUrlEnv);
assert(missingUrlRes.ok === false, 'Blocked when SUPABASE_URL is missing');
assert(missingUrlRes.code === 'ERR_MISSING_STAGING_CONFIG', 'Missing URL code is ERR_MISSING_STAGING_CONFIG');

// 4b. Missing API keys
const missingKeysEnv = {
  SUPABASE_URL: `https://${STAGING_PROJECT_REF}.supabase.co`
};
const missingKeysRes = validateEnvironmentConfig(missingKeysEnv);
assert(missingKeysRes.ok === false, 'Blocked when API keys are missing');
assert(missingKeysRes.code === 'ERR_MISSING_STAGING_CONFIG', 'Missing keys code is ERR_MISSING_STAGING_CONFIG');

// Verify enforceStartupEnvironmentGuard throws for missing config
try {
  enforceStartupEnvironmentGuard({ env: missingUrlEnv, exitOnError: false });
  assert(false, 'Should have thrown for missing SUPABASE_URL');
} catch (err) {
  assert(err.code === 'ERR_MISSING_STAGING_CONFIG', 'enforceStartupEnvironmentGuard threw ERR_MISSING_STAGING_CONFIG');
}

// --------------------------------------------------------------------------
// 5. UNIT TESTS: UNAPPROVED FOREIGN REF
// --------------------------------------------------------------------------
console.log('\n--- 5. UNAPPROVED FOREIGN REF ---');

const foreignEnv = {
  SUPABASE_URL: 'https://foreignprojectref123456.supabase.co',
  SUPABASE_ANON_KEY: stagingAnonKey
};
const foreignRes = validateEnvironmentConfig(foreignEnv);
assert(foreignRes.ok === false, 'Blocked foreign unapproved Supabase ref');
assert(foreignRes.code === 'ERR_INVALID_STAGING_REF', 'Foreign ref code is ERR_INVALID_STAGING_REF');

// --------------------------------------------------------------------------
// 6. UNIT TESTS: PRODUCTION RENDER ENVIRONMENT (REQUIREMENT 6)
// --------------------------------------------------------------------------
console.log('\n--- 6. PRODUCTION RENDER ENVIRONMENT (AUTHORIZATION) ---');

const prodRenderEnv = {
  RENDER: 'true',
  SUPABASE_URL: `https://${PRODUCTION_PROJECT_REF}.supabase.co`,
  SUPABASE_ANON_KEY: prodAnonKey
};

assert(isProductionRender(prodRenderEnv) === true, 'Detected Render production platform');
const prodRenderRes = validateEnvironmentConfig(prodRenderEnv);
assert(prodRenderRes.ok === true, 'Production Render allowed to connect to Production database');
assert(prodRenderRes.mode === 'PRODUCTION_RENDER', 'Mode is PRODUCTION_RENDER');
assert(prodRenderRes.isProduction === true, 'isProduction flag is true');

// --------------------------------------------------------------------------
// 7. PROCESS INTEGRATION TESTS: REAL CHILD PROCESS EXECUTION
// --------------------------------------------------------------------------
console.log('\n--- 7. INTEGRATION TESTS (REAL NODE PROCESS LIFECYCLE) ---');

const indexScriptPath = path.join(__dirname, 'index.js');

// 7a. Test process fails and exits immediately when given Production URL
const childProdRun = spawnSync(process.execPath, [indexScriptPath], {
  env: {
    ...process.env,
    SUPABASE_URL: `https://${PRODUCTION_PROJECT_REF}.supabase.co`,
    SUPABASE_ANON_KEY: stagingAnonKey,
    PORT: '5998'
  },
  encoding: 'utf8',
  timeout: 5000
});

assert(childProdRun.status === 1, `Child process exited with code 1 when pointing to Production (got ${childProdRun.status})`);
assert(
  (childProdRun.stderr || '').includes('DATSAN_STARTUP_GUARD_FATAL') || (childProdRun.stdout || '').includes('DATSAN_STARTUP_GUARD_FATAL'),
  'Output contains DATSAN_STARTUP_GUARD_FATAL banner'
);
assert(
  (childProdRun.stderr || '').includes('PRODUCTION_REF_FORBIDDEN') || (childProdRun.stdout || '').includes('PRODUCTION_REF_FORBIDDEN'),
  'Output explicitly states PRODUCTION_REF_FORBIDDEN'
);

// 7b. Test process fails when missing SUPABASE_URL
const childMissingRun = spawnSync(process.execPath, [indexScriptPath], {
  env: {
    ...process.env,
    SUPABASE_URL: '',
    PORT: '5997'
  },
  encoding: 'utf8',
  timeout: 5000
});

assert(childMissingRun.status === 1, `Child process exited with code 1 when missing configuration (got ${childMissingRun.status})`);
assert(
  (childMissingRun.stderr || '').includes('MISSING_STAGING_CONFIG') || (childMissingRun.stdout || '').includes('MISSING_STAGING_CONFIG'),
  'Output explicitly states MISSING_STAGING_CONFIG'
);

// --------------------------------------------------------------------------
// SUMMARY
// --------------------------------------------------------------------------
console.log('\n========================================================================');
console.log(`TEST RESULTS: ${passCount} PASSED, ${failCount} FAILED (TOTAL: ${passCount + failCount})`);
console.log('========================================================================');

if (failCount > 0) {
  process.exit(1);
} else {
  console.log('🎉 ALL STARTUP ENVIRONMENT GUARD TESTS PASSED PERFECTLY!\n');
}
