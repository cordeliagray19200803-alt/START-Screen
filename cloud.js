(() => {
  'use strict';

  const CONFIG = window.MEDICAL_CLOUD_CONFIG || {};
  const SESSION_PREFIX = 'medical-secure-auth';
  let client = null;
  let user = null;
  let publicToken = null;
  let publicEnabled = false;
  let consentAcceptedAt = null;
  let saveTimer = null;
  let initialized = false;
  let inactivityTimer = null;

  function configured(){
    return Boolean(
      CONFIG.supabaseUrl && CONFIG.supabaseAnonKey &&
      !String(CONFIG.supabaseUrl).includes('YOUR_') &&
      !String(CONFIG.supabaseAnonKey).includes('YOUR_')
    );
  }

  function setStatus(message, type='normal'){
    document.querySelectorAll('[data-cloud-status]').forEach(el => {
      el.textContent = message;
      el.dataset.statusType = type;
    });
  }

  function endpoint(name){
    return `${String(CONFIG.supabaseUrl).replace(/\/$/, '')}/functions/v1/${name}`;
  }

  function secureHeaders(session, extra={}){
    const headers = {
      'Content-Type':'application/json',
      'apikey':CONFIG.supabaseAnonKey,
      'X-Requested-With':'MedicalInfoWeb',
      ...extra
    };
    if(session?.access_token) headers.Authorization = `Bearer ${session.access_token}`;
    return headers;
  }

  async function parseResponse(response){
    let body = null;
    try { body = await response.json(); } catch { body = null; }
    if(!response.ok){
      const message = body?.error || body?.message || `通信エラー（${response.status}）`;
      throw new Error(message);
    }
    return body;
  }

  async function getSession(){
    if(!client) await init();
    const {data:{session}, error} = await client.auth.getSession();
    if(error) throw error;
    return session;
  }

  function startInactivityWatch(){
    const minutes = Number(CONFIG.inactivityMinutes) > 0 ? Number(CONFIG.inactivityMinutes) : 15;
    const reset = () => {
      clearTimeout(inactivityTimer);
      if(!user) return;
      inactivityTimer = setTimeout(async () => {
        try {
          await signOut();
          alert('安全のため、操作がなかったので自動的にログアウトしました。');
          location.replace('index.html');
        } catch(err){ console.error(err); }
      }, minutes * 60 * 1000);
    };
    ['pointerdown','keydown','touchstart','scroll'].forEach(name => {
      window.addEventListener(name, reset, {passive:true});
    });
    document.addEventListener('visibilitychange', () => {
      if(!document.hidden) reset();
    });
    reset();
  }

  async function init(){
    if(initialized) return {configured:configured(), user, consentAcceptedAt, publicEnabled};
    initialized = true;
    if(!configured()){
      setStatus('クラウド保存の設定が必要です', 'error');
      return {configured:false, user:null};
    }
    if(!window.supabase?.createClient){
      setStatus('クラウド接続用ライブラリを読み込めません', 'error');
      return {configured:false, user:null};
    }

    client = window.supabase.createClient(CONFIG.supabaseUrl, CONFIG.supabaseAnonKey, {
      auth:{
        persistSession:true,
        autoRefreshToken:true,
        detectSessionInUrl:true,
        flowType:'pkce',
        storage:window.sessionStorage,
        storageKey:SESSION_PREFIX
      }
    });

    const {data:{session}} = await client.auth.getSession();
    user = session?.user || null;
    client.auth.onAuthStateChange((_event, sessionNow) => {
      user = sessionNow?.user || null;
      publicToken = null;
      window.dispatchEvent(new CustomEvent('medical-auth-changed', {detail:{user}}));
    });
    startInactivityWatch();
    setStatus(user ? '安全なクラウドへ接続済み' : 'ログインしてください', user ? 'saved' : 'normal');
    return {configured:true, user};
  }

  async function signUp(email, password){
    if(!client) await init();
    if(!client) throw new Error('クラウド設定が完了していません。');
    const redirectTo = new URL('index.html', window.location.href).href;
    const {data, error} = await client.auth.signUp({
      email,
      password,
      options:{emailRedirectTo:redirectTo}
    });
    if(error) throw error;
    user = data.user || null;
    return data;
  }

  async function signIn(email, password){
    if(!client) await init();
    if(!client) throw new Error('クラウド設定が完了していません。');
    const {data, error} = await client.auth.signInWithPassword({email, password});
    if(error) throw error;
    user = data.user || null;
    return data;
  }

  async function reauthenticate(password){
    if(!user?.email) throw new Error('ログイン情報を確認できません。');
    const {data, error} = await client.auth.signInWithPassword({email:user.email, password});
    if(error) throw new Error('パスワードが一致しません。');
    user = data.user || user;
    return data;
  }

  async function signOut(){
    clearTimeout(inactivityTimer);
    clearTimeout(saveTimer);
    if(client){
      const {error} = await client.auth.signOut({scope:'local'});
      if(error) throw error;
    }
    user = null;
    publicToken = null;
    publicEnabled = false;
    consentAcceptedAt = null;
    sessionStorage.removeItem(SESSION_PREFIX);
  }

  function getUser(){ return user; }
  function getPublicToken(){ return publicToken; }
  function isPublicEnabled(){ return publicEnabled; }
  function getConsentAcceptedAt(){ return consentAcceptedAt; }

  function hasMeaningfulData(value){
    if(!value || typeof value !== 'object') return false;
    return Boolean(value?.basic?.name || value?.basic?.birthDate ||
      ['handbooks','conditions','surgeries','allergies','devices','implants','mobility','regularMeds','prnMeds','topicalMeds','hospitals','supports','contacts']
        .some(key => Array.isArray(value[key]) && value[key].length));
  }

  async function authenticatedFetch(method, body=null, extraHeaders={}){
    const session = await getSession();
    if(!session) throw new Error('ログインが必要です。');
    const response = await fetch(endpoint('profile'), {
      method,
      headers:secureHeaders(session, extraHeaders),
      cache:'no-store',
      credentials:'omit',
      referrerPolicy:'no-referrer',
      body:body === null ? undefined : JSON.stringify(body)
    });
    return parseResponse(response);
  }

  async function loadOwnProfile(){
    setStatus('暗号化された情報を読み込み中…', 'saving');
    const result = await authenticatedFetch('GET');
    publicToken = result.publicToken || null;
    publicEnabled = Boolean(result.publicEnabled);
    consentAcceptedAt = result.consentAcceptedAt || null;
    setStatus(result.medicalData ? '暗号化された情報を読み込みました' : 'まだ医療情報は登録されていません', result.medicalData ? 'saved' : 'normal');
    return {
      data:result.medicalData || null,
      publicToken,
      publicEnabled,
      updatedAt:result.updatedAt || null,
      consentAcceptedAt
    };
  }

  async function saveOwnProfile(medicalData, consent=null){
    if(!user) throw new Error('保存するにはログインが必要です。');
    setStatus('暗号化して保存中…', 'saving');
    const result = await authenticatedFetch('PUT', {
      medicalData,
      consent:consent || undefined,
      consentVersion:CONFIG.consentVersion || 'v1'
    });
    publicToken = result.publicToken || publicToken;
    publicEnabled = Boolean(result.publicEnabled);
    consentAcceptedAt = result.consentAcceptedAt || consentAcceptedAt;
    setStatus('暗号化してクラウドへ保存済み', 'saved');
    window.dispatchEvent(new CustomEvent('medical-cloud-saved', {
      detail:{publicToken, publicEnabled, updatedAt:result.updatedAt}
    }));
    return {
      data:medicalData,
      publicToken,
      publicEnabled,
      updatedAt:result.updatedAt,
      consentAcceptedAt
    };
  }

  function scheduleSave(medicalData, delay=1200, consent=null){
    clearTimeout(saveTimer);
    if(!user){ setStatus('ログイン後に保存できます', 'normal'); return; }
    if(!consentAcceptedAt && !consent){
      setStatus('同意後にクラウド保存されます', 'normal');
      return;
    }
    setStatus('変更を保存待ち…', 'saving');
    saveTimer = setTimeout(() => {
      saveOwnProfile(medicalData, consent).catch(err => {
        console.error(err);
        setStatus('クラウド保存に失敗しました', 'error');
      });
    }, delay);
  }

  async function flushSave(medicalData, consent=null){
    clearTimeout(saveTimer);
    return saveOwnProfile(medicalData, consent);
  }

  async function deleteOwnProfile(){
    setStatus('登録情報と公開リンクを削除中…', 'saving');
    await authenticatedFetch('DELETE', null, {'X-Confirm-Delete':'DELETE'});
    publicToken = null;
    publicEnabled = false;
    consentAcceptedAt = null;
    setStatus('稼働中の登録情報を削除しました', 'saved');
  }

  async function rotatePublicLink(){
    const result = await authenticatedFetch('POST', {action:'rotate_public_link'});
    publicToken = result.publicToken;
    publicEnabled = Boolean(result.publicEnabled);
    return result;
  }

  async function setPublicEnabled(enabled){
    const result = await authenticatedFetch('POST', {action:enabled ? 'enable_public_link' : 'disable_public_link'});
    publicEnabled = Boolean(result.publicEnabled);
    if(result.publicToken) publicToken = result.publicToken;
    return result;
  }

  async function loadPublicProfile(token){
    if(!configured() || !token) return null;
    const response = await fetch(endpoint('emergency'), {
      method:'POST',
      headers:secureHeaders(null),
      cache:'no-store',
      credentials:'omit',
      referrerPolicy:'no-referrer',
      body:JSON.stringify({token})
    });
    const result = await parseResponse(response);
    return {
      data:result.medicalData || null,
      updatedAt:result.updatedAt || null
    };
  }

  function publicUrl(token=publicToken){
    if(!token) return '';
    const url = new URL('display.html', window.location.href);
    url.hash = `t=${encodeURIComponent(token)}`;
    return url.href;
  }

  window.MedicalCloud = Object.freeze({
    configured, init, signUp, signIn, reauthenticate, signOut,
    getUser, getPublicToken, isPublicEnabled, getConsentAcceptedAt,
    loadOwnProfile, saveOwnProfile, scheduleSave, flushSave,
    deleteOwnProfile, rotatePublicLink, setPublicEnabled,
    loadPublicProfile, publicUrl, hasMeaningfulData, setStatus
  });
})();
