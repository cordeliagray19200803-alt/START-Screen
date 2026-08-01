import {
  adminClient, audit, decryptJson, json, responseHeaders, requireAllowedOrigin,
  requestFingerprints, sha256
} from '../_shared/security.ts';

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response(null, {status:204, headers:responseHeaders(req)});
  const originError = requireAllowedOrigin(req);
  if (originError) return originError;
  if (req.method !== 'POST') return json(req, 405, {error:'使用できない操作です。'});

  const admin = adminClient();
  try {
    const raw = await req.text();
    if (raw.length > 2048) return json(req, 413, {error:'リクエストが大きすぎます。'});
    const token = String(JSON.parse(raw || '{}').token || '');
    if (!/^[A-Za-z0-9_-]{40,60}$/.test(token)) return json(req, 404, {error:'緊急医療情報を確認できません。'});

    const tokenHash = await sha256(token);
    const {data:row, error} = await admin.from('secure_medical_profiles')
      .select('id,owner_id,public_ciphertext,public_iv,public_enabled,updated_at')
      .eq('public_token_hash',tokenHash)
      .eq('public_enabled',true)
      .maybeSingle();
    if (error || !row) return json(req, 404, {error:'緊急医療情報を確認できません。公開が停止されている可能性があります。'});

    const fp = await requestFingerprints(req);
    const {data:allowed, error:rateError} = await admin.rpc('check_emergency_rate_limit', {
      p_profile_id:row.id,
      p_ip_hash:fp.ipHash,
      p_limit:60,
      p_window_seconds:600
    });
    if (rateError) throw rateError;
    if (!allowed) {
      await audit(admin, req, 'public_rate_limited', row.owner_id, row.id, 'blocked');
      return json(req, 429, {error:'短時間にアクセスが集中しています。少し待ってから再度開いてください。'});
    }

    const medicalData = await decryptJson(row.public_ciphertext, row.public_iv, `public:${row.owner_id}`);
    await admin.from('emergency_access_log').insert({
      profile_id:row.id,
      ip_hash:fp.ipHash,
      user_agent_hash:fp.userAgentHash,
      result:'success'
    });
    await audit(admin, req, 'public_read', row.owner_id, row.id);
    return json(req, 200, {medicalData, updatedAt:row.updated_at});
  } catch (error) {
    console.error(error);
    return json(req, 500, {error:'緊急医療情報を安全に読み込めませんでした。'});
  }
});
