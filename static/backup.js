'use strict';
const BACKUP_FORMAT='csa-traffic-encrypted-backup';
const BACKUP_ITERATIONS=600000;
const BACKUP_AAD=new TextEncoder().encode('CSA Traffic encrypted backup v1');
const MAX_BACKUP_BYTES=131072;

function base64(bytes){return btoa(Array.from(bytes,b=>String.fromCharCode(b)).join(''))}
function unbase64(value){
  if(typeof value!=='string'||value.length>90000||value.length%4||!/^[A-Za-z0-9+/]*={0,2}$/.test(value))throw Error('backupInvalid');
  try{return Uint8Array.from(atob(value),c=>c.charCodeAt(0))}catch(_){throw Error('backupInvalid')}
}
function requireBackupCrypto(){if(!globalThis.crypto?.subtle)throw Error('backupCryptoUnavailable')}
async function backupKey(password,salt){
  requireBackupCrypto();
  const bytes=new TextEncoder().encode(password);
  try{
    const material=await crypto.subtle.importKey('raw',bytes,'PBKDF2',false,['deriveKey']);
    return await crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:BACKUP_ITERATIONS,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  }finally{bytes.fill(0)}
}
async function encryptBackup(snapshot,password){
  requireBackupCrypto();
  if(typeof password!=='string'||password.length<12)throw Error('backupPasswordShort');
  const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
  const bytes=new TextEncoder().encode(JSON.stringify(snapshot));
  try{
    if(bytes.length>16000)throw Error('backupInvalid');
    const key=await backupKey(password,salt);
    const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:BACKUP_AAD,tagLength:128},key,bytes);
    return {format:BACKUP_FORMAT,version:1,cipher:'AES-256-GCM',kdf:'PBKDF2-SHA256',iterations:BACKUP_ITERATIONS,salt:base64(salt),iv:base64(iv),ciphertext:base64(new Uint8Array(ciphertext))};
  }finally{bytes.fill(0)}
}
async function decryptBackup(text,password){
  requireBackupCrypto();
  if(typeof text!=='string'||text.length>MAX_BACKUP_BYTES)throw Error('backupInvalid');
  let envelope;
  try{envelope=JSON.parse(text)}catch(_){throw Error('backupInvalid')}
  if(!envelope||envelope.format!==BACKUP_FORMAT||envelope.version!==1||envelope.cipher!=='AES-256-GCM'||envelope.kdf!=='PBKDF2-SHA256'||envelope.iterations!==BACKUP_ITERATIONS)throw Error('backupInvalid');
  const salt=unbase64(envelope.salt),iv=unbase64(envelope.iv),ciphertext=unbase64(envelope.ciphertext);
  if(salt.length!==16||iv.length!==12||ciphertext.length<16||ciphertext.length>16016)throw Error('backupInvalid');
  const key=await backupKey(password,salt);
  let plaintext;
  try{plaintext=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:BACKUP_AAD,tagLength:128},key,ciphertext))}catch(_){throw Error('backupDecryptFailed')}
  try{
    const snapshot=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plaintext));
    if(!snapshot||snapshot.format!=='csa-traffic-settings'||snapshot.version!==1||!snapshot.settings||!snapshot.credentials)throw Error();
    return snapshot;
  }catch(_){throw Error('backupInvalid')}finally{plaintext.fill(0)}
}

let backupMessage=null;
function localizeBackup(){
  $('#backup-export-fields').disabled=settingsBusy||!connection.configured;
  $('#backup-restore-fields').disabled=settingsBusy;
  $('#backup-setuphint').hidden=connection.configured;
  if(backupMessage)$('#backup-message').textContent=backupMessage.raw?translateError(backupMessage.key):t(backupMessage.key);
}
function backupFeedback(key,kind='success',raw=false){
  backupMessage={key,raw};
  const node=$('#backup-message');node.hidden=false;node.className='settings-message '+kind;
  localizeBackup();
}
function clearBackupPasswords(){for(const id of ['#backup-password','#backup-confirm','#restore-password'])$(id).value=''}
function initializeBackup(){
  $('#backup-export-form').addEventListener('submit',event=>{event.preventDefault();exportBackup()});
  $('#backup-restore-form').addEventListener('submit',event=>{event.preventDefault();importBackup()});
  $('#settings-dialog').addEventListener('close',()=>{clearBackupPasswords();$('#restore-file').value=''});
}
async function exportBackup(){
  if(settingsBusy||!connection.configured)return;
  if(!$('#backup-export-form').reportValidity())return;
  if($('#backup-password').value!==$('#backup-confirm').value){backupFeedback('backupPasswordMismatch','failure');return}
  setSettingsBusy(true);backupFeedback('backupEncrypting','pending');
  let snapshot=null;
  try{
    requireBackupCrypto();
    snapshot=await api('/api/settings/backup',{method:'POST',body:'{}'});
    snapshot.preferences={language};
    const encrypted=await encryptBackup(snapshot,$('#backup-password').value);
    const url=URL.createObjectURL(new Blob([JSON.stringify(encrypted,null,2)+'\n'],{type:'application/json'}));
    const link=document.createElement('a');link.href=url;link.download='csa-traffic-'+new Date().toISOString().slice(0,10)+'.csabackup';link.click();
    setTimeout(()=>URL.revokeObjectURL(url),1000);
    backupFeedback('backupDownloaded');
  }catch(error){backupFeedback(error.message,'failure',true)}finally{
    if(snapshot?.credentials){snapshot.credentials.accessKeyId='';snapshot.credentials.secretAccessKey=''}
    clearBackupPasswords();setSettingsBusy(false);
  }
}
async function importBackup(){
  if(settingsBusy)return;
  if(!$('#backup-restore-form').reportValidity())return;
  const file=$('#restore-file').files[0];
  if(!file||file.size>MAX_BACKUP_BYTES){backupFeedback('backupInvalid','failure');return}
  setSettingsBusy(true);backupFeedback('backupRestoring','pending');
  let snapshot=null;
  try{
    snapshot=await decryptBackup(await file.text(),$('#restore-password').value);
    const result=await api('/api/settings/restore',{method:'POST',body:JSON.stringify(snapshot)});
    if(result.language)applyLanguage(result.language);
    await finishConnection(result,'backupRestored');
    $('#restore-file').value='';
  }catch(e){
    if($('#settings-dialog').open)backupFeedback(e.message,'failure',true);
    else error(e.message);
  }finally{
    if(snapshot?.credentials){snapshot.credentials.accessKeyId='';snapshot.credentials.secretAccessKey=''}
    clearBackupPasswords();setSettingsBusy(false);
  }
}
