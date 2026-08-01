import {
  adminClient, authenticatedUser, audit, decryptJson, encryptJson,
  json, responseHeaders, jwtIssuedRecently, publicSubset, randomToken, requireAllowedOrigin,
  sanitizeMedicalData, sha256
} from '../_shared/security.ts';

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response(null, {status:204, headers:responseHeaders(req)});
  const originError = requireAllowedOrigin(req);
  if (originError) return originError;

  const admin = adminClient();
  let auth;
  try { auth = await authenticatedUser(req); }
  catch { return json(req, 401, {error:'ログインが必要です。'}); }

  const ownerId = auth.user.id;
  try {
    if (req.method === 'GET') {
      const {data:row, error} = await admin.from('secure_medical_profiles').select('*').eq('owner_id', ownerId).maybeSingle();
      if (error) throw error;
      if (!row) return json(req, 200, {medicalData:null, publicEnabled:false, consentAcceptedAt:null});
      const medicalData = await decryptJson(row.private_ciphertext, row.private_iv, `private:${ownerId}`);
      const publicToken = await decryptJson(row.public_token_ciphertext, row.public_token_iv, `token:${ownerId}`) as string;
      await audit(admin, req, 'owner_read', ownerId, row.id);
      return json(req, 200, {
        medicalData,
        publicToken,
        publicEnabled:row.public_enabled,
        consentAcceptedAt:row.consent_accepted_at,
        updatedAt:row.updated_at,
        revision:row.revision
      });
    }

    if (req.method === 'PUT') {
      const rawText = await req.text();
      if (new TextEncoder().encode(rawText).byteLength > 150_000) return json(req, 413, {error:'入力内容が大きすぎます。'});
      const body = JSON.parse(rawText || '{}');
      const medicalData = sanitizeMedicalData(body.medicalData);
      const {data:existing, error:existingError} = await admin.from('secure_medical_profiles').select('*').eq('owner_id', ownerId).maybeSingle();
      if (existingError) throw existingError;

      const consentProvided = body.consent?.sensitiveData === true && body.consent?.emergencyDisplay === true;
      if (!existing?.consent_accepted_at && !consentProvided) {
        return json(req, 400, {error:'保存には個人情報の取扱いと緊急表示への同意が必要です。'});
      }

      const token = existing
        ? await decryptJson(existing.public_token_ciphertext, existing.public_token_iv, `token:${ownerId}`) as string
        : randomToken();
      const privateEncrypted = await encryptJson(medicalData, `private:${ownerId}`);
      const publicEncrypted = await encryptJson(publicSubset(medicalData), `public:${ownerId}`);
      const tokenEncrypted = await encryptJson(token, `token:${ownerId}`);
      const tokenHash = await sha256(token);
      const now = new Date().toISOString();
      const consentAcceptedAt = existing?.consent_accepted_at || now;
      const consentVersion = String(body.consentVersion || existing?.consent_version || 'v1').slice(0,80);

      const payload = {
        owner_id:ownerId,
        private_ciphertext:privateEncrypted.ciphertext,
        private_iv:privateEncrypted.iv,
        public_ciphertext:publicEncrypted.ciphertext,
        public_iv:publicEncrypted.iv,
        public_token_hash:tokenHash,
        public_token_ciphertext:tokenEncrypted.ciphertext,
        public_token_iv:tokenEncrypted.iv,
        public_enabled:existing?.public_enabled ?? true,
        consent_version:consentVersion,
        consent_accepted_at:consentAcceptedAt,
        revision:(existing?.revision || 0) + 1,
        updated_at:now
      };

      const {data:row, error} = await admin.from('secure_medical_profiles').upsert(payload,{onConflict:'owner_id'}).select('id,updated_at,revision,public_enabled').single();
      if (error) throw error;

      if (consentProvided && (!existing?.consent_accepted_at || existing?.consent_version !== consentVersion)) {
        await admin.from('consent_records').insert({
          owner_id:ownerId,
          profile_id:row.id,
          consent_version:consentVersion,
          sensitive_data_consent:true,
          emergency_display_consent:true
        });
      }
      await audit(admin, req, existing ? 'owner_update' : 'owner_create', ownerId, row.id);
      return json(req, 200, {
        publicToken:token,
        publicEnabled:row.public_enabled,
        consentAcceptedAt,
        updatedAt:row.updated_at,
        revision:row.revision
      });
    }

    if (req.method === 'POST') {
      const body = await req.json().catch(() => ({}));
      const {data:existing, error} = await admin.from('secure_medical_profiles').select('*').eq('owner_id', ownerId).single();
      if (error || !existing) return json(req, 404, {error:'医療情報が登録されていません。'});

      if (body.action === 'rotate_public_link') {
        const token = randomToken();
        const tokenEncrypted = await encryptJson(token, `token:${ownerId}`);
        const {data:row, error:updateError} = await admin.from('secure_medical_profiles').update({
          public_token_hash:await sha256(token),
          public_token_ciphertext:tokenEncrypted.ciphertext,
          public_token_iv:tokenEncrypted.iv,
          public_enabled:true,
          updated_at:new Date().toISOString()
        }).eq('owner_id',ownerId).select('id,public_enabled,updated_at').single();
        if (updateError) throw updateError;
        await audit(admin, req, 'public_link_rotated', ownerId, row.id);
        return json(req, 200, {publicToken:token, publicEnabled:true, updatedAt:row.updated_at});
      }

      if (body.action === 'disable_public_link' || body.action === 'enable_public_link') {
        const enabled = body.action === 'enable_public_link';
        const {data:row, error:updateError} = await admin.from('secure_medical_profiles').update({public_enabled:enabled,updated_at:new Date().toISOString()}).eq('owner_id',ownerId).select('id,public_enabled,updated_at').single();
        if (updateError) throw updateError;
        const token = await decryptJson(existing.public_token_ciphertext, existing.public_token_iv, `token:${ownerId}`) as string;
        await audit(admin, req, enabled ? 'public_link_enabled' : 'public_link_disabled', ownerId, row.id);
        return json(req, 200, {publicToken:token, publicEnabled:enabled, updatedAt:row.updated_at});
      }

      return json(req, 400, {error:'操作を確認できません。'});
    }

    if (req.method === 'DELETE') {
      if (req.headers.get('x-confirm-delete') !== 'DELETE') return json(req, 400, {error:'削除確認が不足しています。'});
      if (!jwtIssuedRecently(auth.token, 300)) return json(req, 401, {error:'削除前にパスワードを再確認してください。'});
      const {data:row} = await admin.from('secure_medical_profiles').select('id').eq('owner_id',ownerId).maybeSingle();
      if (row) {
        await admin.from('emergency_access_log').delete().eq('profile_id',row.id);
        await admin.from('emergency_rate_limits').delete().eq('profile_id',row.id);
      }
      await admin.from('consent_records').delete().eq('owner_id',ownerId);
      await admin.from('security_audit').delete().eq('owner_id',ownerId);
      const {error} = await admin.from('secure_medical_profiles').delete().eq('owner_id',ownerId);
      if (error) throw error;
      return json(req, 200, {deleted:true});
    }

    return json(req, 405, {error:'使用できない操作です。'});
  } catch (error) {
    console.error(error);
    await audit(admin, req, 'profile_error', ownerId, null, 'error');
    return json(req, 500, {error:'安全な処理を完了できませんでした。時間をおいて再度お試しください。'});
  }
});
