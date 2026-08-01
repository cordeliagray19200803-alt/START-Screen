import { createClient, SupabaseClient, User } from 'npm:@supabase/supabase-js@2';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function env(name: string): string {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

export function allowedOrigin(req: Request): string | null {
  const origin = req.headers.get('origin');
  if (!origin) return null;
  const allowed = env('ALLOWED_ORIGINS').split(',').map(v => v.trim()).filter(Boolean);
  return allowed.includes(origin) ? origin : null;
}

export function responseHeaders(req: Request): HeadersInit {
  const origin = allowedOrigin(req);
  return {
    ...(origin ? {'Access-Control-Allow-Origin': origin} : {}),
    'Access-Control-Allow-Headers': 'authorization, apikey, content-type, x-requested-with, x-confirm-delete',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Max-Age': '600',
    'Vary': 'Origin',
    'Cache-Control': 'no-store, max-age=0',
    'Pragma': 'no-cache',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    'Content-Type': 'application/json; charset=utf-8'
  };
}

export function json(req: Request, status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {status, headers: responseHeaders(req)});
}

export function requireAllowedOrigin(req: Request): Response | null {
  if (!allowedOrigin(req)) return json(req, 403, {error:'許可されていない接続元です。'});
  return null;
}

export function adminClient(): SupabaseClient {
  return createClient(env('SUPABASE_URL'), env('SUPABASE_SERVICE_ROLE_KEY'), {
    auth:{persistSession:false, autoRefreshToken:false}
  });
}

export async function authenticatedUser(req: Request): Promise<{user: User, token: string}> {
  const auth = req.headers.get('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) throw new Error('AUTH_REQUIRED');
  const authClient = createClient(env('SUPABASE_URL'), env('SUPABASE_ANON_KEY'), {
    global:{headers:{Authorization:`Bearer ${token}`}},
    auth:{persistSession:false, autoRefreshToken:false}
  });
  const {data:{user}, error} = await authClient.auth.getUser(token);
  if (error || !user) throw new Error('AUTH_REQUIRED');
  return {user, token};
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i=0; i<binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function base64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

async function derivedKey(context: string): Promise<CryptoKey> {
  const master = base64ToBytes(env('MEDICAL_DATA_KEY'));
  if (master.byteLength < 32) throw new Error('MEDICAL_DATA_KEY must decode to at least 32 bytes');
  const material = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({
    name:'HKDF',
    hash:'SHA-256',
    salt:encoder.encode('medical-info-encryption-v1'),
    info:encoder.encode(context)
  }, material, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}

export async function encryptJson(value: unknown, context: string): Promise<{ciphertext:string, iv:string}> {
  const key = await derivedKey(context);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(JSON.stringify(value));
  const encrypted = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, plaintext);
  return {ciphertext:bytesToBase64(new Uint8Array(encrypted)), iv:bytesToBase64(iv)};
}

export async function decryptJson(ciphertext: string, iv: string, context: string): Promise<unknown> {
  const key = await derivedKey(context);
  const decrypted = await crypto.subtle.decrypt(
    {name:'AES-GCM', iv:base64ToBytes(iv)},
    key,
    base64ToBytes(ciphertext)
  );
  return JSON.parse(decoder.decode(decrypted));
}

export function randomToken(): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(value));
  return base64Url(new Uint8Array(digest));
}

export async function hmac(value: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(env('AUDIT_HASH_KEY')),
    {name:'HMAC', hash:'SHA-256'}, false, ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(value));
  return base64Url(new Uint8Array(signature));
}

function cleanText(value: unknown, max=500): string {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    .trim()
    .slice(0, max);
}

function stringArray(value: unknown, maxItems=30, maxLength=500): string[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, maxItems).map(v => cleanText(v, maxLength)).filter(Boolean);
}

function objectArray(value: unknown, allowed: Record<string, number>, maxItems=30): Record<string,string>[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, maxItems).map(item => {
    const source = item && typeof item === 'object' ? item as Record<string,unknown> : {};
    const result: Record<string,string> = {};
    for (const [key, limit] of Object.entries(allowed)) result[key] = cleanText(source[key], limit);
    return result;
  }).filter(item => Object.values(item).some(Boolean));
}

export type MedicalData = {
  basic: Record<string,string>;
  disabilities: string[];
  currentDiseases: string[];
  pastHistories: string[];
  surgeries: string[];
  emergencyNotes: string[];
  handbook: string;
  regularMeds: Record<string,string>[];
  prnMeds: Record<string,string>[];
  topicalMeds: Array<{name:string; frequency:string; note:string; parts:string[]}>;
  hospitals: Record<string,string>[];
  supports: Record<string,string>[];
  emergencyContacts: Record<string,string>[];
  sharing: Record<string,boolean>;
};

function sanitizeAny(value: unknown, depth=0): unknown {
  if (depth > 10) return null;
  if (typeof value === 'string') return cleanText(value, 4000);
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean' || value === null) return value;
  if (Array.isArray(value)) return value.slice(0, 120).map(v => sanitizeAny(v, depth + 1));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [rawKey, rawValue] of Object.entries(value as Record<string, unknown>).slice(0, 120)) {
      const key = rawKey.replace(/[^a-zA-Z0-9_\-]/g, '').slice(0, 80);
      if (!key) continue;
      out[key] = sanitizeAny(rawValue, depth + 1);
    }
    return out;
  }
  return null;
}

export function sanitizeMedicalData(input: unknown): MedicalData {
  const result = sanitizeAny(input) as MedicalData;
  if (!result || typeof result !== 'object') throw new Error('入力内容を確認できません。');
  const bytes = encoder.encode(JSON.stringify(result)).byteLength;
  if (bytes > 140_000) throw new Error('入力内容が大きすぎます。');
  return result;
}

export function publicSubset(data: MedicalData): Partial<MedicalData> {
  // このアプリに入力する項目は、本人がNFCで救急時に表示するための情報です。
  // 公開停止はpublic_enabledで制御し、URLトークンはDBへ平文保存しません。
  return data;
}

export async function requestFingerprints(req: Request): Promise<{ipHash:string, userAgentHash:string}> {
  const forwarded = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('cf-connecting-ip') || 'unknown';
  const ua = req.headers.get('user-agent') || 'unknown';
  return {ipHash:await hmac(`ip:${forwarded}`), userAgentHash:await hmac(`ua:${ua}`)};
}

export async function audit(
  admin: SupabaseClient,
  req: Request,
  eventType: string,
  ownerId: string | null,
  profileId: string | null,
  result='success'
): Promise<void> {
  try {
    const fp = await requestFingerprints(req);
    await admin.from('security_audit').insert({
      owner_id:ownerId,
      profile_id:profileId,
      event_type:eventType,
      result,
      ip_hash:fp.ipHash,
      user_agent_hash:fp.userAgentHash
    });
  } catch (error) {
    console.error('audit failed', error);
  }
}

export function jwtIssuedRecently(token: string, maxAgeSeconds=300): boolean {
  try {
    const part = token.split('.')[1].replace(/-/g,'+').replace(/_/g,'/');
    const payload = JSON.parse(atob(part.padEnd(Math.ceil(part.length/4)*4, '=')));
    const iat = Number(payload.iat || 0);
    return iat > 0 && (Math.floor(Date.now()/1000) - iat) <= maxAgeSeconds;
  } catch { return false; }
}
