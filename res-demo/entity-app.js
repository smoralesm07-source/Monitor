(() => {
'use strict';
const DATA=window.RES_DATA, INS=window.RES_INSIGHTS, ENT=window.RES_ENTITIES||[];
if(!DATA||!INS||!ENT.length)return;
const REG=DATA.regions;
const fmt=n=>new Intl.NumberFormat('es-CL').format(Math.round(Number(n)||0));
const money=n=>'$'+fmt(n);
const esc=s=>String(s??'—').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const norm=s=>(s||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toUpperCase();
const fmtDate=s=>{if(!s)return'—';const [y,m,d]=s.split('-');return`${d}/${m}/${y}`};
const standardCaps=new Set([100000,200000,300000,500000,1000000,1500000,2000000,3000000,4000000,5000000,6000000,7000000,8000000,10000000,15000000,20000000,30000000]);
const PHEN_COHORTS={
 'metro-pattern':['PROVIDENCIA_SPA_1M','LAS_CONDES_SPA_1M','SANTIAGO_SPA_1M'],
 'arica':['ARICA'],'macul':['MACUL_SPA_5M'],'huechuraba':['HUECHURABA'],'victoria':['VICTORIA']
};
let entityFilter='all';

function typeMedian(code){const x=DATA.typesYTD.find(t=>t.code===code);return x?Number(x.median):Number(DATA.overview.medianCapital);}
function cohortBand(n){return n>=10?['Cohorte alta','high']:n>=3?['Cohorte media','medium']:['Cohorte baja','low'];}
function lexicalTokens(name){const n=norm(name);return INS.vocabulary.filter(v=>n.includes(norm(v.token))).map(v=>v.token).slice(0,6);}
function field(label,value,meta=''){return`<div class="entity-field"><span>${esc(label)}</span><b>${esc(value)}</b><small>${esc(meta)}</small></div>`;}

function openEntity(e){
 const median=typeMedian(e.company_code),ratio=median?Number(e.capital)/median:0;
 const territorySame=e.social_commune===e.tax_commune&&Number(e.social_region)===Number(e.tax_region);
 const cohort=cohortBand(Number(e.cohort_size)),tokens=lexicalTokens(e.legal_name),isStd=standardCaps.has(Number(e.capital));
 const chips=[e.company_code,`Capital ${isStd?'estándar':'no estándar'}`,cohort[0],e.lag_sii_days===0?'SII mismo día':`SII +${e.lag_sii_days}d`,territorySame?'Territorio coincidente':'Territorio difiere'].map(x=>`<span class="entity-chip">${esc(x)}</span>`).join('');
 const body=document.getElementById('entityDrawerBody'); if(!body)return;
 body.innerHTML=`<div class="entity-title"><div><h2>${esc(e.legal_name)}</h2><p>${esc(e.rut)} · ${esc(e.company_code)}</p></div><span class="entity-cohort ${cohort[1]}">${cohort[0]}</span></div>
 <div class="entity-chips">${chips}</div>
 <div class="entity-kpis"><div><span>Capital</span><b>${money(e.capital)}</b><small>${ratio.toFixed(1)}× mediana ${esc(e.company_code)}</small></div><div><span>Constitución</span><b>${fmtDate(e.constitution_date)}</b><small>${esc(e.social_commune)}</small></div><div><span>Cohorte exacta</span><b>${fmt(e.cohort_size)}</b><small>mismo día + comuna + tipo + capital</small></div><div><span>Rezago SII</span><b>${e.lag_sii_days} d</b><small>desde constitución</small></div></div>
 <section class="entity-section"><h3>Identificación</h3><div class="field-grid">${field('RUT',e.rut,'Dato RES')}${field('Razón social',e.legal_name,'Dato RES')}${field('Tipo societario',e.company_code,'Dato RES')}${field('Capital declarado',money(e.capital),'Dato RES')}</div></section>
 <section class="entity-section"><h3>Cronología registral</h3><div class="timeline-mini"><div><i></i><b>Constitución</b><span>${fmtDate(e.constitution_date)}</span><small>día 0</small></div><div><i></i><b>Registro</b><span>${fmtDate(e.registry_date)}</span><small>+${e.lag_registry_days} días</small></div><div><i></i><b>Aprobación SII</b><span>${fmtDate(e.sii_approval_date)}</span><small>+${e.lag_sii_days} días</small></div></div></section>
 <section class="entity-section"><h3>Territorio</h3><div class="field-grid">${field('Comuna social',e.social_commune,REG[e.social_region])}${field('Comuna tributaria',e.tax_commune,REG[e.tax_region])}${field('Consistencia territorial',territorySame?'Coincidente':'Diferente','Comparación social vs tributaria')}</div></section>
 <section class="entity-section"><h3>Caracterización de capital</h3><div class="field-grid">${field('Capital declarado',money(e.capital),'Dato RES')}${field('Mediana del tipo',money(median),`Mediana YTD ${esc(e.company_code)}`)}${field('Relación vs mediana',ratio.toFixed(2)+'×','Caracterización derivada')}${field('Capital estandarizado',isStd?'Sí':'No','Catálogo de montos recurrentes')}</div></section>
 <section class="entity-section"><h3>Contexto de cohorte</h3><div class="cohort-box"><strong>${fmt(e.cohort_size)} sociedades</strong><span>comparten exactamente <b>${fmtDate(e.constitution_date)} + ${esc(e.social_commune)} + ${esc(e.company_code)} + ${money(e.capital)}</b>.</span><small>Caracteriza simultaneidad estructural; no implica vínculo entre sociedades.</small></div></section>
 <section class="entity-section"><h3>Razón social</h3>${tokens.length?`<div class="token-row">${tokens.map(t=>`<span>${esc(t)}</span>`).join('')}</div><p class="muted">Coincidencias con vocabulario emergente de la ventana reciente.</p>`:'<p class="muted">Sin coincidencias con el vocabulario emergente seleccionado para esta demo.</p>'}</section>
 <section class="entity-section provenance"><h3>Proveniencia</h3><p><b>Fuente:</b> Registro de Empresas y Sociedades · réplica <code>aml_res_company</code> · corte 31/07/2026.</p><p>La ficha no contiene socios, representantes, administradores, personas naturales ni inferencias de actividad económica.</p></section>`;
 document.getElementById('entityDrawer').classList.add('open');
}
function entityButtons(ents){
 if(!ents.length)return'<div class="empty">La demo no incluye sociedades individuales para esta señal. En Atlas se consultará el universo completo.</div>';
 return`<div class="entity-mini-list">${ents.slice(0,12).map(e=>`<button class="entity-mini" data-rut="${e.rut}"><span><b>${esc(e.legal_name)}</b><small>${esc(e.rut)} · ${esc(e.social_commune)}</small></span><em>${money(e.capital)}</em></button>`).join('')}</div>`;
}
function bindMini(root=document){root.querySelectorAll('.entity-mini').forEach(b=>b.onclick=ev=>{ev.stopPropagation();const e=ENT.find(x=>x.rut===b.dataset.rut);if(e)openEntity(e);});}
function appendEntitiesToAnalyticDrawer(ents,title='Sociedades observadas'){
 setTimeout(()=>{
   const body=document.getElementById('drawerBody'); if(!body||body.querySelector('.entity-drill-section'))return;
   const sec=document.createElement('div'); sec.className='drawer-section entity-drill-section';
   sec.innerHTML=`<h4>${title}</h4><p class="muted">Muestra real navegable vinculada a esta señal. Abre una sociedad para ver el dato granular y su contexto de cohorte.</p>${entityButtons(ents)}`;
   const notice=body.querySelector('.notice'); if(notice)body.insertBefore(sec,notice); else body.appendChild(sec);
   bindMini(sec);
 },0);
}
function entitiesForPhen(id){const cs=PHEN_COHORTS[id]||[];return ENT.filter(e=>cs.includes(e.cohort));}
function entitiesForCommune(c){return ENT.filter(e=>e.social_commune===c).slice(0,10);}

function initSearch(){
 const input=document.getElementById('entitySearch'),box=document.getElementById('entitySearchResults'); if(!input||!box)return;
 input.oninput=()=>{const q=norm(input.value.trim());if(q.length<2){box.classList.remove('open');box.innerHTML='';return;}const rows=ENT.filter(e=>norm(e.legal_name).includes(q)||norm(e.rut).includes(q)).slice(0,8);box.innerHTML=rows.length?rows.map(e=>`<button data-rut="${e.rut}"><b>${esc(e.legal_name)}</b><span>${esc(e.rut)} · ${esc(e.social_commune)} · ${money(e.capital)}</span></button>`).join(''):`<div class="search-empty"><b>Sin coincidencia en la muestra demo.</b><span>La integración Atlas consultará el universo completo de aml_res_company.</span></div>`;box.classList.add('open');box.querySelectorAll('button').forEach(b=>b.onclick=()=>{box.classList.remove('open');input.value='';openEntity(ENT.find(e=>e.rut===b.dataset.rut));});};
 document.addEventListener('click',e=>{if(!e.target.closest('.entity-search-shell'))box.classList.remove('open');});
}
function renderExplorer(){
 const el=document.getElementById('entityExplorer'); if(!el)return;
 const rows=(entityFilter==='all'?ENT:ENT.filter(e=>e.cohort===entityFilter)).slice(0,20);
 el.innerHTML=rows.map(e=>`<button class="entity-card" data-rut="${e.rut}"><div><span class="entity-type">${esc(e.company_code)}</span><b>${esc(e.legal_name)}</b><small>${esc(e.rut)}</small></div><div class="entity-card-meta"><span>${esc(e.social_commune)}</span><strong>${money(e.capital)}</strong><small>${fmtDate(e.constitution_date)} · cohorte ${e.cohort_size}</small></div></button>`).join('');
 el.querySelectorAll('.entity-card').forEach(b=>b.onclick=()=>openEntity(ENT.find(e=>e.rut===b.dataset.rut)));
}
function initFilters(){
 document.querySelectorAll('#entityFilterTabs button').forEach(b=>b.onclick=()=>{entityFilter=b.dataset.cohort;document.querySelectorAll('#entityFilterTabs button').forEach(x=>x.classList.toggle('active',x===b));renderExplorer();});
}

function installDrilldowns(){
 document.addEventListener('click',e=>{
   const phen=e.target.closest('.phenomenon-card'); if(phen){appendEntitiesToAnalyticDrawer(entitiesForPhen(phen.dataset.id));return;}
   const life=e.target.closest('.life-lane button[data-id]'); if(life){appendEntitiesToAnalyticDrawer(entitiesForPhen(life.dataset.id));return;}
   const accel=e.target.closest('#accelTable tr[data-c]'); if(accel){appendEntitiesToAnalyticDrawer(entitiesForCommune(accel.dataset.c));return;}
   const signal=e.target.closest('.signal-row[data-commune]'); if(signal){appendEntitiesToAnalyticDrawer(entitiesForCommune(signal.dataset.commune));return;}
   const rec=e.target.closest('#recurrentTable tr[data-i]'); if(rec){const x=INS.recurrentClusters[+rec.dataset.i];appendEntitiesToAnalyticDrawer(ENT.filter(z=>z.social_commune===x.commune&&z.company_code===x.type&&Number(z.capital)===Number(x.capital)));return;}
   const vocab=e.target.closest('.vocab[data-token]'); if(vocab){appendEntitiesToAnalyticDrawer(ENT.filter(z=>norm(z.legal_name).includes(norm(vocab.dataset.token))),'Sociedades de la muestra con este token');}
 },true);
}
function init(){
 const count=document.getElementById('entitySampleCount'); if(count)count.textContent=ENT.length;
 initSearch();initFilters();renderExplorer();installDrilldowns();
 const close=document.getElementById('entityDrawerClose');if(close)close.onclick=()=>document.getElementById('entityDrawer').classList.remove('open');
 document.addEventListener('keydown',e=>{if(e.key==='Escape')document.getElementById('entityDrawer').classList.remove('open');});
 const badge=document.getElementById('healthBadge');if(badge)badge.textContent='Datos + fichas operativas ✓';
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
})();