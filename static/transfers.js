'use strict';
let transferState=null;
const TRANSFER_FIELDS={timestamp:'Timestamp',direction:'Direction',protocol:'Protocol',sourceip:'Source IP',sourceport:'Source Port',destinationip:'Destination IP',destinationport:'Destination Port',fqdns:'FQDNs',hostname:'Hostname',servername:'Server Name',action:'Action',ruleid:'Rule ID',rulesetid:'Ruleset ID',firstpackettimestamp:'First Packet Timestamp',lastpackettimestamp:'Last Packet Timestamp',packetssent:'Packets Sent',packetsreceived:'Packets Received',bytessent:'Bytes Sent',bytesreceived:'Bytes Received',destinationcountry:'Destination Country',sourcecountry:'Source Country',awsregion:'AWS Region',datacenter:'Data Center',appid:'App ID',applicationids:'Application IDs',applicationentityname:'Application Entity Name',privateappgroupid:'Private App Group ID',privateflow:'Private Flow',trafficsource:'Traffic Source',internalclientip:'Internal Client IP',externalclientip:'External Client IP',requestmethod:'Request Method',url:'URL',statuscode:'Status Code',contenttype:'Content Type',requestsize:'Request Size',responsesize:'Response Size',responsebodysize:'Response Body Size',identities:'Identities',policyidentitylabel:'Policy Identity Label',identitytypes:'Identity Types',identitytype:'Identity Type',fwblockreason:'FW Block Reason',forwardingmethod:'Forwarding Method',egressip:'Egress IP',egress:'Egress'};

function closeTransfers(){if($('#transfers-dialog').open)$('#transfers-dialog').close();transferState=null}
function openTransfers(ip){
  if(!current||loading)return;
  const query=new URLSearchParams(current.query);query.set('ip',ip);query.set('revision',current.revision||'0');
  transferState={query,ip,page:1,sort:'latest',data:null,busy:false,failure:'',sequence:0,expanded:new Set(),details:new Map()};
  $('#transfers-dialog').showModal();fetchTransfers();
}
async function fetchTransfers(){
  const state=transferState;if(!state)return;
  const sequence=++state.sequence;state.busy=true;state.failure='';state.expanded.clear();state.details.clear();renderTransfers();
  const query=new URLSearchParams(state.query);query.set('page',state.page);query.set('sort',state.sort);
  try{const data=await api('/api/transfers?'+query);if(transferState!==state||sequence!==state.sequence)return;state.data=data}
  catch(e){if(transferState!==state||sequence!==state.sequence)return;state.data=null;state.failure=e.message}
  finally{if(transferState===state&&sequence===state.sequence){state.busy=false;renderTransfers()}}
}
function transferBytes(value){return value===null?t('transferMissingValue'):bytes(value)}
function transferTotal(item){return item.sent===null&&item.received===null?t('transferMissingValue'):bytes((item.sent||0)+(item.received||0))+(item.sent===null||item.received===null?' *':'')}
function transferProtocol(value){return ({'6':'TCP (6)','17':'UDP (17)','1':'ICMP (1)','58':'ICMPv6 (58)'})[value]||value||'—'}
function transferTime(ts){return new Intl.DateTimeFormat(locale,{timeZone:'Europe/Prague',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'}).format(new Date(ts*1000))}
function transferDL(entries){
  const list=document.createElement('dl');list.className='transfer-fields';
  for(const [label,value] of entries){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=String(value);list.append(dt,dd)}return list;
}
async function toggleTransfer(item){
  const state=transferState;if(!state)return;
  if(state.expanded.has(item.id)){state.expanded.delete(item.id);renderTransfers();return}
  state.expanded.add(item.id);renderTransfers();
  if(state.details.has(item.id))return;
  state.details.set(item.id,{busy:true});
  const query=new URLSearchParams(state.query);query.set('event',item.id);query.set('eventRevision',item.eventRevision);query.set('hydrate','1');
  try{const detail=await api('/api/transfers?'+query);if(transferState!==state)return;state.details.set(item.id,{data:detail});if(detail.available){const f=detail.fields;item.available=true;item.destination=f.destinationip||'';item.port=f.destinationport||'';item.hostname=(f.hostname||f.servername||f.fqdns||'').slice(0,500);item.protocol=f.protocol||f.requestmethod||'';item.action=f.action||''}}
  catch(e){if(transferState!==state)return;state.details.set(item.id,{failure:e.message});if(['transfersChanged','transferUnavailable'].includes(e.message))state.failure=e.message}
  if(transferState===state)renderTransfers();
}
function renderTransfers(){
  const state=transferState;if(!state)return;
  const q=state.query, data=state.data;
  $('#transfers-title').textContent=t('transferTitle',{ip:state.ip||t('unknownIP')});
  $('#transfers-context').textContent=t(q.get('source')==='proxy'?'proxy':'firewall')+' · '+transferTime(new Date(q.get('from')).getTime()/1000)+' - '+transferTime(new Date(q.get('to')).getTime()/1000)+' · Europe/Prague\n'+t('trafficType')+': '+t(({all:'allTraffic',internet:'internet',private:'private',unknown:'unknownTraffic'})[q.get('scope')])+(q.get('subnet')?' · '+t('csvIP')+': '+q.get('subnet'):'')+(q.get('identity')?' · '+t('identity')+': '+q.get('identity'):'');
  $('#transfers-sort').value=state.sort;$('#transfers-sort').disabled=state.busy;
  $('#transfers-status').textContent=state.busy?t('transferLoading'):state.failure?translateError(state.failure):data?t('transferSummary',{n:fmt.format(data.totals.records),received:bytes(data.totals.received),sent:bytes(data.totals.sent)}):'';
  $('#transfers-status').classList.toggle('failure',Boolean(state.failure));
  $('#transfers-legacy').hidden=!data||data.totals.detailed===data.totals.records;
  $('#transfers-missing').hidden=!data||!data.totals.missing;
  $('#transfers-refresh').hidden=state.failure!=='transfersChanged'&&state.failure!=='transferUnavailable';
  $('#transfers-previous').disabled=state.busy||!data||state.page<=1;$('#transfers-next').disabled=state.busy||!data||state.page>=data.pages;
  $('#transfers-page').textContent=data?t('transferPage',{page:state.page,pages:data.pages}):'';
  const focused=document.activeElement?.dataset.transferId, scroll=$('#transfers-dialog').scrollTop;
  const tbody=$('#transfers-rows');tbody.replaceChildren();
  if(state.busy||!data)return;
  if(!data.items.length){const row=document.createElement('tr'),cell=document.createElement('td');cell.colSpan=7;cell.textContent=t('emptyTable');row.append(cell);tbody.append(row)}
  for(const item of data.items){
    const tr=document.createElement('tr');tr.className='transfer-row';
    const first=document.createElement('td'),button=document.createElement('button');button.className='transfer-link';button.type='button';button.dataset.transferId=item.id;button.textContent=(state.expanded.has(item.id)?'▾ ':'▸ ')+transferTime(item.ts);button.setAttribute('aria-expanded',String(state.expanded.has(item.id)));if(state.expanded.has(item.id))button.setAttribute('aria-controls','transfer-detail-'+item.id);button.setAttribute('aria-label',t('transferExpand',{time:transferTime(item.ts)}));button.addEventListener('click',()=>toggleTransfer(item));first.append(button);tr.append(first);
    const missing=item.available?t('transferMissingValue'):t('transferNotLoaded');
    const destination=item.destination?(item.destination.includes(':')?'['+item.destination+']':item.destination)+(item.port?':'+item.port:''):missing;
    for(const value of [destination+(item.hostname?'\n'+item.hostname:''),transferProtocol(item.protocol),item.action||'—',transferBytes(item.received),transferBytes(item.sent),transferTotal(item)]){const td=document.createElement('td');td.textContent=value;tr.append(td)}
    tr.addEventListener('click',e=>{if(!e.target.closest('button'))toggleTransfer(item)});tbody.append(tr);
    if(!state.expanded.has(item.id))continue;
    const detailRow=document.createElement('tr'),cell=document.createElement('td');cell.colSpan=7;cell.className='transfer-detail';cell.id='transfer-detail-'+item.id;
    cell.append(transferDL([[t('sourceIP'),item.ip||t('unknownIP')],[t('identity'),item.identities.join(', ')||t('transferMissingValue')],[t('trafficType'),t(({private:'private',internet:'internet',unknown:'unknownTraffic'})[item.scope])],[t('transferUTC'),new Date(item.ts*1000).toISOString()],[t('csvReceived'),item.received===null?t('transferMissingValue'):item.received],[t('csvSent'),item.sent===null?t('transferMissingValue'):item.sent]]));
    const detail=state.details.get(item.id),message=document.createElement('p');message.className='transfer-note';
    if(!detail||detail.busy)message.textContent=t('transferLoading');
    else if(detail.failure){message.textContent=translateError(detail.failure);const retry=document.createElement('button');retry.type='button';retry.className='secondary';retry.textContent=t('transferRetry');retry.addEventListener('click',()=>{state.details.delete(item.id);state.expanded.delete(item.id);toggleTransfer(item)});cell.append(retry)}
    else if(!detail.data.available)message.textContent=t('transferLegacy');
    else{message.textContent=t('transferRawFields');cell.append(transferDL(Object.entries(detail.data.fields).map(([key,value])=>[TRANSFER_FIELDS[key]||key,value])));if(detail.data.truncated.length){const warning=document.createElement('p');warning.textContent=t('transferTruncated',{fields:detail.data.truncated.map(k=>TRANSFER_FIELDS[k]||k).join(', ')});warning.className='transfer-note';cell.append(warning)}}
    cell.prepend(message);detailRow.append(cell);tbody.append(detailRow);
  }
  if(focused)tbody.querySelector('[data-transfer-id="'+focused+'"]')?.focus({preventScroll:true});
  $('#transfers-dialog').scrollTop=scroll;
}

function initializeTransfers(){
$('#transfers-close').addEventListener('click',closeTransfers);
$('#transfers-dialog').addEventListener('close',()=>{transferState=null});
$('#transfers-sort').addEventListener('change',()=>{if(transferState){transferState.sort=$('#transfers-sort').value;transferState.page=1;fetchTransfers()}});
$('#transfers-previous').addEventListener('click',()=>{if(transferState){transferState.page--;fetchTransfers()}});
$('#transfers-next').addEventListener('click',()=>{if(transferState){transferState.page++;fetchTransfers()}});
$('#transfers-refresh').addEventListener('click',()=>{closeTransfers();load()});

}
