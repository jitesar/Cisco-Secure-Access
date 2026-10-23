'use strict';
const SAVED_FILTERS_KEY='csa-saved-filters-v1';
let savedFilters=[],savedFilterMessage='';
function validateSavedFilters(value){
  if(!Array.isArray(value)||value.length>100)throw Error('savedFiltersInvalid');
  const names=new Set();
  for(const item of value){
    if(!item||typeof item.name!=='string'||!item.name.trim()||item.name.length>80||names.has(item.name)||
      !['firewall','proxy'].includes(item.source)||!['all','subnet','identity'].includes(item.mode)||
      !['all','internet','private','unknown'].includes(item.scope)||
      typeof item.subnet!=='string'||item.subnet.length>100000||typeof item.identity!=='string'||item.identity.length>16384||
      !(item.hours===null||[1,24,72,168,720].includes(item.hours))||
      typeof item.from!=='string'||typeof item.to!=='string'||!Number.isFinite(Date.parse(item.from))||!Number.isFinite(Date.parse(item.to)))throw Error('savedFiltersInvalid');
    names.add(item.name);
  }
  return value;
}
function copySavedFilters(value){
  return validateSavedFilters(value).map(({name,source,mode,scope,subnet,identity,hours,from,to})=>({name,source,mode,scope,subnet,identity,hours,from,to}));
}
function readSavedFilters(){
  try{const raw=localStorage.getItem(SAVED_FILTERS_KEY);return copySavedFilters(raw?JSON.parse(raw):[])}catch(_){throw Error('savedFiltersStorageRead')}
}
function stageSavedFilterRestore(snapshot){
  // Old backups do not change the browser's saved filters.
  if(!Object.prototype.hasOwnProperty.call(snapshot,'savedFilters'))return null;
  const incoming=copySavedFilters(snapshot.savedFilters),existing=readSavedFilters();
  const merged=new Map(existing.map(item=>[item.name,item]));
  for(const item of incoming)merged.set(item.name,item);
  const next=[...merged.values()];if(next.length>100)throw Error('savedFiltersLimit');
  const staged=JSON.stringify(next);let previous;
  try{previous=localStorage.getItem(SAVED_FILTERS_KEY);localStorage.setItem(SAVED_FILTERS_KEY,staged)}catch(_){throw Error('savedFiltersStorage')}
  return {previous,staged};
}
function rollbackSavedFilterRestore(transaction){
  if(!transaction)return;
  // Do not overwrite a newer edit made in a different application tab.
  if(localStorage.getItem(SAVED_FILTERS_KEY)!==transaction.staged)return;
  if(transaction.previous===null)localStorage.removeItem(SAVED_FILTERS_KEY);
  else localStorage.setItem(SAVED_FILTERS_KEY,transaction.previous);
}
function finishSavedFilterRestore(transaction){
  if(!transaction)return;
  savedFilters=readSavedFilters();renderSavedFilters();
}
function savedFilterFeedback(key){savedFilterMessage=key;$('#saved-filter-message').textContent=t(key)}
function renderSavedFilters(selected=$('#saved-filter-select').value){
  $('#saved-filter-select').replaceChildren(new Option(t('savedFilterChoose'),''),...savedFilters.map(item=>new Option(item.name,item.name)));
  $('#saved-filter-select').value=savedFilters.some(item=>item.name===selected)?selected:'';
  const empty=!$('#saved-filter-select').value;
  $('#saved-filter-load').disabled=empty;$('#saved-filter-delete').disabled=empty;
  if(savedFilterMessage)$('#saved-filter-message').textContent=t(savedFilterMessage);
}
function persistSavedFilters(next,selected){
  validateSavedFilters(next);
  try{localStorage.setItem(SAVED_FILTERS_KEY,JSON.stringify(next))}catch(_){throw Error('savedFiltersStorage')}
  savedFilters=next;renderSavedFilters(selected);
}
function saveSearchFilter(){
  try{
    const name=$('#saved-filter-name').value.trim();if(!name||name.length>80)throw Error('savedFilterNameRequired');
    const query=params(),quick=document.querySelector('[data-hours].selected');
    const item={name,source,mode:$('#mode').value,scope:query.get('scope'),subnet:query.get('subnet'),identity:query.get('identity'),hours:quick?Number(quick.dataset.hours):null,from:query.get('from'),to:query.get('to')};
    const next=savedFilters.filter(filter=>filter.name!==name);next.push(item);
    if(next.length>100)throw Error('savedFiltersLimit');
    persistSavedFilters(next,name);savedFilterFeedback('savedFilterSaved');
  }catch(e){savedFilterFeedback(e.message)}
}
async function applySavedFilter(){
  const item=savedFilters.find(filter=>filter.name===$('#saved-filter-select').value);if(!item)return;
  source=item.source;
  document.querySelectorAll('[data-source]').forEach(button=>button.classList.toggle('active',button.dataset.source===source));
  $('#sourcedesc').textContent=t(source==='proxy'?'sourceProxy':'sourceFirewall');
  $('#mode').value=item.mode;$('#subnet').value=item.subnet;
  if(item.identity&&![...$('#identity').options].some(option=>option.value===item.identity))$('#identity').add(new Option(item.identity,item.identity));
  $('#identity').value=item.identity;
  $('#subnetfield').hidden=item.mode!=='subnet';$('#identityfield').hidden=item.mode!=='identity';
  $('#scope').value=source==='proxy'?'all':item.scope;$('#scope').disabled=source==='proxy';
  if(item.hours!==null)preset(item.hours);
  else{updateDateBounds();$('#from').value=localValue(new Date(item.from));$('#to').value=localValue(new Date(item.to));document.querySelectorAll('[data-hours]').forEach(button=>button.classList.remove('selected'))}
  $('#saved-filter-name').value=item.name;
  try{params()}catch(e){savedFilterFeedback(e.message==='windowError'?'savedFilterExpired':e.message);return}
  savedFilterFeedback('savedFilterLoaded');await load();
}
function initializeSavedFilters(){
  try{const raw=localStorage.getItem(SAVED_FILTERS_KEY);savedFilters=validateSavedFilters(raw?JSON.parse(raw):[])}catch(_){savedFilterFeedback('savedFiltersStorageRead')}
  renderSavedFilters();
  $('#saved-filter-save').addEventListener('click',saveSearchFilter);
  $('#saved-filter-load').addEventListener('click',applySavedFilter);
  $('#saved-filter-delete').addEventListener('click',()=>{
    try{const name=$('#saved-filter-select').value;if(!name)return;persistSavedFilters(savedFilters.filter(item=>item.name!==name),'');$('#saved-filter-name').value='';savedFilterFeedback('savedFilterDeleted')}catch(e){savedFilterFeedback(e.message)}
  });
  $('#saved-filter-select').addEventListener('change',()=>{const selected=$('#saved-filter-select').value;$('#saved-filter-name').value=selected;renderSavedFilters(selected)});
  window.addEventListener('storage',event=>{
    if(event.key!==SAVED_FILTERS_KEY&&event.key!==null)return;
    try{savedFilters=validateSavedFilters(event.newValue?JSON.parse(event.newValue):[]);renderSavedFilters()}catch(_){savedFilterFeedback('savedFiltersStorageRead')}
  });
}
