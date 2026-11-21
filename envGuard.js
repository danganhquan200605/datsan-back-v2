/**
 * DATSANONLINE — STARTUP ENVIRONMENT GUARD
 * 
 * Objectives:
 * 1. Enforces that in Local/Development mode, backend ONLY connects to Supabase Staging (fllbhjovifmzyfjubifx).
 * 2. Hard block if Production Project Ref (ckrmfyuymuvaiymfxvhj) is detected anywhere.
 * 3. Throws fatal error if Staging config is missing (zero fallback to Production).
 * 4. Deep inspection of Supabase API URLs, Database URLs, connection strings, hostnames, and JWT claims.
 * 5. Safely allows Production Render environment to connect to production database.
 */

const STAGING_PROJECT_REF = 'fllbhjovifmzyfjubifx';
const PRODUCTION_PROJECT_REF = 'ckrmfyuymuvaiymfxvhj';

/**
 * Extracts Supabase Project Ref from a given URL or hostname
 * Supports:
 * - https://<ref>.supabase.co
 * - http://<ref>.supabase.co
 * - db.<ref>.supabase.co
 * - postgresql://postgres.<ref>:<pass>@...pooler.supabase.com:...
 * - postgresql://postgres:<pass>@db.<ref>.supabase.co:...
 */
function extractProjectRefFromUrl(urlString) {
  if (!urlString || typeof urlString !== 'string') return null;
  const str = urlString.trim();

  // 1. https://<ref>.supabase.co
  const apiMatch = str.match(/https?:\/\/([a-z0-9_-]+)\.supabase\.co/i);
  if (apiMatch) return apiMatch[1].toLowerCase();

  // 2. db.<ref>.supabase.co
  const dbMatch = str.match(/db\.([a-z0-9_-]+)\.supabase\.co/i);
  if (dbMatch) return dbMatch[1].toLowerCase();

  // 3. Pooler username: postgres.<ref>
  const poolerMatch = str.match(/postgres\.([a-z0-9_-]+):[^@]*@/i);
  if (poolerMatch) return poolerMatch[1].toLowerCase();

  return null;
}

/**
 * Decodes Supabase JWT token and extracts project ref from claim (e.g. payload.ref)
 */
function extractRefFromJwt(jwtString) {
  if (!jwtString || typeof jwtString !== 'string') return null;
  const parts = jwtString.trim().split('.');
  if (parts.length !== 3) return null;
  try {
    const payloadJson = Buffer.from(parts[1], 'base64').toString('utf8');
    const payload = JSON.parse(payloadJson);
    return (payload.ref || '').toLowerCase() || null;
  } catch {
    return null;
  }
}

/**
 * Detects if the current environment is Production Render
 */
function isProductionRender(env = process.env) {
  // Render automatically sets RENDER=true on all services
  if (String(env.RENDER).toLowerCase() === 'true') return true;
  if (Boolean(env.RENDER_SERVICE_ID) || Boolean(env.RENDER_INSTANCE_ID) || Boolean(env.RENDER_SERVICE_NAME)) return true;
  // Explicitly configured production deployment (e.g. on Render build)
  if (env.DATSAN_RUNTIME_ENV === 'production') return true;
  if (env.APP_ENV === 'production' && env.IS_LOCAL !== 'true') return true;
  if (env.NODE_ENV === 'production' && env.IS_LOCAL !== 'true' && !env.LOCAL_DEV && !env.IS_DEV) {
    if (!['localhost', '127.0.0.1'].includes(env.HOSTNAME || env.HOST || '')) {
      return true;
    }
  }
  return false;
}

/**
 * Validates the environment configuration against safety guard rules
 */
function validateEnvironmentConfig(env = process.env) {
  // Requirement: FINANCIAL_MODE must be strictly 'DEMO' across all environments
  const financialMode = String(env.FINANCIAL_MODE || '').trim().toUpperCase();
  if (financialMode !== 'DEMO') {
    return {
      ok: false,
      code: 'ERR_INVALID_FINANCIAL_MODE',
      mode: isProductionRender(env) ? 'PRODUCTION_RENDER' : 'LOCAL_DEV',
      error: `INVALID_FINANCIAL_MODE: FINANCIAL_MODE is required to be strictly 'DEMO' (detected: "${env.FINANCIAL_MODE || ''}"). Backend startup refused to prevent real financial transactions.`
    };
  }

  const isProd = isProductionRender(env);

  // Requirement 6: Do not apply Staging-only rule to Production Render
  if (isProd) {
    return {
      ok: true,
      mode: 'PRODUCTION_RENDER',
      isProduction: true,
      stagingRef: null,
      message: 'Running in Production Render environment. Production database connection authorized.'
    };
  }

  // Local / Development Environment checks:
  const localMode = 'LOCAL_DEV';

  // Requirement 3: Check missing Staging configuration (no fallback allowed)
  const supabaseUrl = String(env.SUPABASE_URL || '').trim();
  if (!supabaseUrl) {
    return {
      ok: false,
      code: 'ERR_MISSING_STAGING_CONFIG',
      mode: localMode,
      error: 'MISSING_STAGING_CONFIG: SUPABASE_URL is missing. In Local/Development mode, Staging configuration is mandatory. Startup aborted to prevent fallback to Production.'
    };
  }

  const anonKey = String(env.SUPABASE_ANON_KEY || '').trim();
  const serviceKey = String(env.SUPABASE_SERVICE_ROLE_KEY || '').trim();
  if (!anonKey && !serviceKey) {
    return {
      ok: false,
      code: 'ERR_MISSING_STAGING_CONFIG',
      mode: localMode,
      error: 'MISSING_STAGING_CONFIG: Supabase API keys (SUPABASE_ANON_KEY or SUPABASE_SERVICE_ROLE_KEY) are missing. Startup aborted.'
    };
  }

  // Requirement 2 & 4: Deep inspection for Production Project Ref
  // Scan all environment variables for any occurrence of ckrmfyuymuvaiymfxvhj
  for (const [key, val] of Object.entries(env)) {
    if (typeof val === 'string' && val.toLowerCase().includes(PRODUCTION_PROJECT_REF)) {
      return {
        ok: false,
        code: 'ERR_PRODUCTION_REF_BLOCKED',
        mode: localMode,
        error: `PRODUCTION_REF_FORBIDDEN: Production Project Ref (${PRODUCTION_PROJECT_REF}) detected in environment variable "${key}"! Startup aborted immediately before database connection.`
      };
    }
  }

  // Check Supabase API URL ref
  const apiRef = extractProjectRefFromUrl(supabaseUrl);
  if (apiRef === PRODUCTION_PROJECT_REF) {
    return {
      ok: false,
      code: 'ERR_PRODUCTION_REF_BLOCKED',
      mode: localMode,
      error: `PRODUCTION_REF_FORBIDDEN: Supabase API URL points to Production (${PRODUCTION_PROJECT_REF}). Startup aborted immediately!`
    };
  }

  // Requirement 1: Only allow Supabase Staging (fllbhjovifmzyfjubifx)
  if (apiRef !== STAGING_PROJECT_REF) {
    return {
      ok: false,
      code: 'ERR_INVALID_STAGING_REF',
      mode: localMode,
      error: `INVALID_STAGING_REF: Local/Development environment only permits Supabase Staging (${STAGING_PROJECT_REF}), but detected "${apiRef || 'unknown'}". Startup aborted.`
    };
  }

  // Requirement 4: Check Database Connection URLs
  const dbUrlsToCheck = [
    { name: 'DATABASE_URL', val: env.DATABASE_URL },
    { name: 'SUPABASE_STAGING_DB_URL', val: env.SUPABASE_STAGING_DB_URL },
    { name: 'SUPABASE_DB_URL', val: env.SUPABASE_DB_URL },
    { name: 'PGHOST', val: env.PGHOST },
    { name: 'SUPABASE_STAGING_DB_HOST', val: env.SUPABASE_STAGING_DB_HOST }
  ];

  for (const item of dbUrlsToCheck) {
    if (!item.val) continue;
    const strVal = String(item.val).trim();
    if (strVal.toLowerCase().includes(PRODUCTION_PROJECT_REF)) {
      return {
        ok: false,
        code: 'ERR_PRODUCTION_REF_BLOCKED',
        mode: localMode,
        error: `PRODUCTION_REF_FORBIDDEN: Database connection config "${item.name}" points to Production (${PRODUCTION_PROJECT_REF}). Startup aborted immediately!`
      };
    }

    // If it points to a remote Supabase DB, ensure it matches Staging
    if (strVal.toLowerCase().includes('supabase.co') || strVal.toLowerCase().includes('supabase.com')) {
      const dbRef = extractProjectRefFromUrl(strVal);
      if (dbRef && dbRef !== STAGING_PROJECT_REF) {
        return {
          ok: false,
          code: 'ERR_INVALID_STAGING_REF',
          mode: localMode,
          error: `INVALID_STAGING_REF: Database URL "${item.name}" points to unapproved Supabase project "${dbRef}". Local/Dev only permits Staging (${STAGING_PROJECT_REF}).`
        };
      }
    }
  }

  // Check JWT key claims if available
  for (const [keyName, keyVal] of [['SUPABASE_ANON_KEY', anonKey], ['SUPABASE_SERVICE_ROLE_KEY', serviceKey]]) {
    if (!keyVal) continue;
    const jwtRef = extractRefFromJwt(keyVal);
    if (jwtRef === PRODUCTION_PROJECT_REF) {
      return {
        ok: false,
        code: 'ERR_PRODUCTION_REF_BLOCKED',
        mode: localMode,
        error: `PRODUCTION_REF_FORBIDDEN: ${keyName} belongs to Production (${PRODUCTION_PROJECT_REF}). Startup aborted immediately!`
      };
    }
    if (jwtRef && jwtRef !== STAGING_PROJECT_REF) {
      return {
        ok: false,
        code: 'ERR_INVALID_STAGING_KEY',
        mode: localMode,
        error: `INVALID_STAGING_KEY: ${keyName} claim ref "${jwtRef}" does not match Staging (${STAGING_PROJECT_REF}). Startup aborted.`
      };
    }
  }

  return {
    ok: true,
    mode: localMode,
    isProduction: false,
    stagingRef: STAGING_PROJECT_REF,
    message: `Startup Environment Guard verified successfully: Connected to Staging (${STAGING_PROJECT_REF}) in Local/Dev mode.`
  };
}

/**
 * Enforces guard at process startup.
 * Halts process or throws error if invalid.
 */
function enforceStartupEnvironmentGuard(options = {}) {
  const env = options.env || process.env;
  const exitOnError = options.exitOnError !== undefined ? options.exitOnError : true;
  const result = validateEnvironmentConfig(env);

  if (!result.ok) {
    const errorBanner = [
      '',
      '========================================================================',
      '🚨 [DATSAN_STARTUP_GUARD_FATAL] APPLICATION STARTUP REFUSED!',
      `Reason: ${result.error}`,
      `Code:   ${result.code}`,
      `Mode:   ${result.mode}`,
      `Time:   ${new Date().toISOString()}`,
      'Action: Aborting startup before any database connection or operation.',
      '========================================================================',
      ''
    ].join('\n');

    console.error(errorBanner);

    if (exitOnError) {
      process.exit(1);
    }
    const err = new Error(result.error);
    err.code = result.code;
    err.guardResult = result;
    throw err;
  }

  console.log(`🛡️  [DATSAN_STARTUP_GUARD] OK: Mode=${result.mode} | TargetRef=${result.stagingRef || 'PRODUCTION'} | Protection Active`);
  return result;
}

module.exports = {
  STAGING_PROJECT_REF,
  PRODUCTION_PROJECT_REF,
  extractProjectRefFromUrl,
  extractRefFromJwt,
  isProductionRender,
  validateEnvironmentConfig,
  enforceStartupEnvironmentGuard
};
