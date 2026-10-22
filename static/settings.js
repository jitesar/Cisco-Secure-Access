'use strict';
let connection={configured:false,csrfToken:''};
let settingsBusy=false,settingsMessage=null;

function connectionChanged(){
  return $('#settings-path').value.trim().replace(/\/+$/,'')!==(connection.s3Path||'').replace(/\/+$/,'') || $('#settings-region').value.trim()!==connection.region;
}

function localizeSettings(){
  const keep=connection.hasCredentials&&!connectionChanged();
  $('#settings-keyhint').textContent=t(keep?'settingsKeepKeys':'settingsNewKeys');
  const replacing=Boolean($('#settings-access').value||$('#settings-secret').value);
  $('#settings-access').required=!keep||replacing;
  $('#settings-secret').required=!keep||replacing;
  localizeBackup();
  if(settingsMessage){
    $('#settings-message').textContent=settingsMessage.raw?translateError(settingsMessage.raw):t(settingsMessage.key);
  }
}

function settingsFeedback(key,kind='success',raw=false){
  settingsMessage={key,raw:raw?key:null};
  const node=$('#settings-message');
  node.hidden=false;
  node.className='settings-message '+kind;
  localizeSettings();
}

function setSettingsBusy(busy){
  settingsBusy=busy;
  $('#settings-fields').disabled=busy;
  $('#settings-close').disabled=busy;
  localizeBackup();
}

function showSettings(){
  $('#settings-path').value=connection.s3Path||'';
  $('#settings-region').value=connection.region||'eu-central-1';
  $('#settings-access').value='';
  $('#settings-secret').value='';
  settingsMessage=null;backupMessage=null;clearBackupPasswords();
  $('#settings-message').hidden=true;$('#backup-message').hidden=true;
  localizeSettings();
  if(!$('#settings-dialog').open)$('#settings-dialog').showModal();$('#settings-path').focus();
}

function updateConnectionUI(){
  $('#setupbanner').hidden=connection.configured;
  $('#filtercontrols').disabled=!connection.configured;
  $('#sync').disabled=!connection.configured||Boolean(lastStatus?.running);
  localizeBackup();
}

async function initializeConnection(){
  initializeBackup();
  $('#open-settings').addEventListener('click',showSettings);
  $('#setup-button').addEventListener('click',showSettings);
  $('#settings-close').addEventListener('click',()=>$('#settings-dialog').close());
  $('#settings-dialog').addEventListener('cancel',event=>{if(settingsBusy)event.preventDefault()});
  $('#settings-dialog').addEventListener('close',()=>{
    $('#settings-access').value='';$('#settings-secret').value='';
  });
  for(const field of ['#settings-path','#settings-region','#settings-access','#settings-secret']){
    $(field).addEventListener('input',()=>{
      settingsMessage=null;$('#settings-message').hidden=true;localizeSettings();
    });
  }
  $('#settings-test').addEventListener('click',()=>submitSettings(false));
  $('#settings-form').addEventListener('submit',event=>{event.preventDefault();submitSettings(true)});
  try{
    connection=await api('/api/settings');
    updateConnectionUI();
    if(connection.configured){await load();await status()}
    else showSettings();
  }catch(e){error(e.message)}
}

async function submitSettings(save){
  if(settingsBusy)return;
  localizeSettings();
  if(!$('#settings-form').reportValidity())return;
  const payload={s3Path:$('#settings-path').value.trim(),region:$('#settings-region').value.trim(),accessKeyId:$('#settings-access').value.trim(),secretAccessKey:$('#settings-secret').value.trim()};
  setSettingsBusy(true);
  settingsFeedback(save?'settingsSaving':'settingsTesting','pending');
  try{
    const result=await api(save?'/api/settings':'/api/settings/test',{method:'POST',body:JSON.stringify(payload)});
    if(!save){settingsFeedback('settingsTestOK');return}
    await finishConnection(result);
  }catch(e){
    if($('#settings-dialog').open)settingsFeedback(e.message,'failure',true);
    else error(e.message);
  }finally{
    // Never retain the submitted key values in application state or browser storage.
    payload.accessKeyId='';payload.secretAccessKey='';
    setSettingsBusy(false);
  }
}

async function finishConnection(result,toastKey='settingsSaved'){
    connection=result;
    requestNo++;current=null;
    $('#total').textContent=$('#received').textContent=$('#sent').textContent=$('#rate').textContent='—';
    $('#recordcount').textContent=t('selectPeriod');$('#top').replaceChildren();$('#export').disabled=true;draw();
    $('#identity').replaceChildren(new Option(t('chooseIdentity'),''));
    $('#mode').value='all';$('#subnetfield').hidden=true;$('#identityfield').hidden=true;
    updateConnectionUI();
    setSettingsBusy(false);
    $('#settings-dialog').close();
    $('#connectiontoast').dataset.i18n=toastKey;$('#connectiontoast').textContent=t(toastKey);$('#connectiontoast').hidden=false;
    error('');
    await load();
    await api('/api/sync',{method:'POST'});
    wasRunning=true;
    await status();
}
