(() => {
  const DB_NAME='medical-info-pwa'; const STORE='profiles'; const KEY='current'; let dbPromise;
  function open(){
    if(!('indexedDB' in window)) return Promise.resolve(null);
    if(dbPromise) return dbPromise;
    dbPromise=new Promise((resolve,reject)=>{const r=indexedDB.open(DB_NAME,1);r.onupgradeneeded=()=>{if(!r.result.objectStoreNames.contains(STORE))r.result.createObjectStore(STORE)};r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error)});
    return dbPromise;
  }
  async function load(){try{const db=await open();if(!db){const v=localStorage.getItem(KEY);return v?JSON.parse(v):null}return await new Promise((resolve,reject)=>{const tx=db.transaction(STORE,'readonly');const r=tx.objectStore(STORE).get(KEY);r.onsuccess=()=>resolve(r.result||null);r.onerror=()=>reject(r.error)})}catch(e){console.error(e);return null}}
  async function save(data){const copy=structuredClone?structuredClone(data):JSON.parse(JSON.stringify(data));try{const db=await open();if(!db){localStorage.setItem(KEY,JSON.stringify(copy));return}await new Promise((resolve,reject)=>{const tx=db.transaction(STORE,'readwrite');tx.objectStore(STORE).put(copy,KEY);tx.oncomplete=resolve;tx.onerror=()=>reject(tx.error)})}catch(e){console.error(e);localStorage.setItem(KEY,JSON.stringify(copy))}}
  async function clear(){try{const db=await open();if(db)await new Promise((resolve,reject)=>{const tx=db.transaction(STORE,'readwrite');tx.objectStore(STORE).delete(KEY);tx.oncomplete=resolve;tx.onerror=()=>reject(tx.error)});localStorage.removeItem(KEY)}catch(e){console.error(e)}}
  window.MedicalDB=Object.freeze({load,save,clear});
})();