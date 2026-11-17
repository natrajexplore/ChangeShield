/**
 * Firebase bootstrap: App, App Check (required by Firebase AI Logic),
 * Authentication, Firestore, Remote Config and the AI Logic instance.
 *
 * Initialisation is LAZY and FAULT-TOLERANT: if the Firebase web config is
 * missing (e.g. a fresh clone without `.env.local`) the app still boots in
 * "local demo mode" — rule-based redaction + the baseline rule auditor run
 * entirely in the browser, and cloud/Firestore features are disabled.
 */
import { initializeApp, type FirebaseApp } from 'firebase/app';
import { initializeAppCheck, ReCaptchaEnterpriseProvider } from 'firebase/app-check';
import { getAuth, signInAnonymously, type Auth, type User } from 'firebase/auth';
import { getFirestore, type Firestore } from 'firebase/firestore';
import { getRemoteConfig, fetchAndActivate, getValue, type RemoteConfig } from 'firebase/remote-config';
import { getAI, GoogleAIBackend, type AI } from 'firebase/ai';
import { clampSettings, DEFAULT_SETTINGS, type AppSettings } from './core';

export type { AppSettings };

const env = import.meta.env;
const firebaseConfig = {
  apiKey: env.VITE_FIREBASE_API_KEY,
  authDomain: env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: env.VITE_FIREBASE_PROJECT_ID,
  storageBucket: env.VITE_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: env.VITE_FIREBASE_MESSAGING_SENDER_ID,
  appId: env.VITE_FIREBASE_APP_ID,
};

const looksReal = (v: string | undefined) => !!v && !/^your-|^0{6,}|^1:0{6,}/.test(v);

/** True when a real-looking Firebase web config was provided at build time. */
export const firebaseConfigured =
  looksReal(firebaseConfig.apiKey) && looksReal(firebaseConfig.projectId) && looksReal(firebaseConfig.appId);

interface FirebaseServices {
  app: FirebaseApp;
  auth: Auth;
  db: Firestore;
  remoteConfig: RemoteConfig;
  ai: AI;
}

let services: FirebaseServices | null = null;
let initError: Error | null = null;

/** Returns the Firebase services, or null in local demo mode / after an init failure. */
export function getFirebase(): FirebaseServices | null {
  if (services || initError) return services;
  if (!firebaseConfigured) {
    initError = new Error('Firebase is not configured (local demo mode)');
    return null;
  }
  try {
    const app = initializeApp(firebaseConfig);

    // App Check — Firebase AI Logic requires it. Local dev / judging builds use the
    // debug provider (accepted by the contest rules). Do NOT add "localhost" to the
    // reCAPTCHA allowed domains; use a debug token instead (per Firebase docs).
    if (env.DEV || env.VITE_APPCHECK_DEBUG === 'true') {
      const debugToken = env.VITE_APPCHECK_DEBUG_TOKEN;
      (self as unknown as { FIREBASE_APPCHECK_DEBUG_TOKEN: string | boolean }).FIREBASE_APPCHECK_DEBUG_TOKEN =
        debugToken && debugToken.length > 0 ? debugToken : true;
    }
    initializeAppCheck(app, {
      provider: new ReCaptchaEnterpriseProvider(env.VITE_RECAPTCHA_ENTERPRISE_SITE_KEY ?? 'unset'),
      isTokenAutoRefreshEnabled: true,
    });

    const remoteConfig = getRemoteConfig(app);
    remoteConfig.settings.minimumFetchIntervalMillis = env.DEV ? 60_000 : 3_600_000;
    remoteConfig.defaultConfig = {
      cloud_model: DEFAULT_SETTINGS.cloudModel,
      enable_cloud_audit: DEFAULT_SETTINGS.enableCloudAudit,
      on_device_chunk_chars: DEFAULT_SETTINGS.chunkChars,
      audit_policy_pack: DEFAULT_SETTINGS.policyPack,
      max_findings: DEFAULT_SETTINGS.maxFindings,
    };

    services = {
      app,
      auth: getAuth(app),
      db: getFirestore(app),
      remoteConfig,
      ai: getAI(app, { backend: new GoogleAIBackend() }),
    };
  } catch (e) {
    initError = e as Error;
    console.warn('[ChangeShield] Firebase init failed — running in local demo mode', e);
  }
  return services;
}

export function firebaseStatus(): { ok: boolean; reason?: string } {
  return getFirebase() ? { ok: true } : { ok: false, reason: initError?.message };
}

/** Firebase AI Logic instance; throws (caught by the pipeline → local fallback) when unavailable. */
export function requireAI(): AI {
  const fb = getFirebase();
  if (!fb) throw new Error(initError?.message ?? 'Firebase unavailable');
  return fb.ai;
}

// ---- Auth ----------------------------------------------------------------------
let signInPromise: Promise<User> | null = null;

/**
 * Wait for persisted auth state to be restored BEFORE deciding to sign in —
 * otherwise every page load creates a brand-new anonymous user and the saved
 * report history disappears. The promise is shared so concurrent callers don't
 * trigger duplicate sign-ins.
 */
export function ensureSignedIn(): Promise<User> {
  const fb = getFirebase();
  if (!fb) return Promise.reject(new Error(initError?.message ?? 'Firebase unavailable'));
  signInPromise ??= (async () => {
    await fb.auth.authStateReady();
    if (fb.auth.currentUser) return fb.auth.currentUser;
    return (await signInAnonymously(fb.auth)).user;
  })().catch((e) => {
    signInPromise = null; // allow a retry later
    throw e;
  });
  return signInPromise;
}

// ---- Remote Config -----------------------------------------------------------
let settingsPromise: Promise<AppSettings> | null = null;

export function loadSettings(): Promise<AppSettings> {
  settingsPromise ??= (async () => {
    const fb = getFirebase();
    if (!fb) return { ...DEFAULT_SETTINGS, enableCloudAudit: false };
    try {
      await fetchAndActivate(fb.remoteConfig);
    } catch (e) {
      console.warn('[ChangeShield] Remote Config fetch failed, using defaults', e);
    }
    const rc = fb.remoteConfig;
    return clampSettings({
      cloudModel: getValue(rc, 'cloud_model').asString(),
      enableCloudAudit: getValue(rc, 'enable_cloud_audit').asBoolean(),
      chunkChars: getValue(rc, 'on_device_chunk_chars').asNumber(),
      policyPack: getValue(rc, 'audit_policy_pack').asString(),
      maxFindings: getValue(rc, 'max_findings').asNumber(),
    });
  })();
  return settingsPromise;
}
