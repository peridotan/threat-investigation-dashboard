const DATA_URL = './data/dashboard.json';
const state = { data: null, view: 'actors', search: '', tactic: '', platform: '', focusId: '', focusOnly: false };
const INVESTIGATION_KEY = 'peridotan-threat-investigation-v1';
let investigation = loadInvestigation();
let externalLaunchContext = null;
const lookups = { actors: new Map(), techniques: new Map(), software: new Map(), campaigns: new Map() };
const ENV_STORE = window.PeridotanEnvironment || null;
let environment = ENV_STORE ? ENV_STORE.load() : {schema_version:'1.0',updated_at:null,platforms:[],products:[],technologies:[]};

const VIEWS = ['actors','techniques','software','campaigns'];
const VIEW_LABELS = { actors:'Threat Actor', techniques:'Technique', software:'Software', campaigns:'Campaign' };
const VIEW_TITLES = { actors:'Threat Actors', techniques:'Techniques', software:'Software', campaigns:'Campaigns' };

const TACTIC_ORDER = [
  'reconnaissance','resource-development','initial-access','execution','persistence',
  'privilege-escalation','stealth','defense-impairment','credential-access','discovery','lateral-movement',
  'collection','command-and-control','exfiltration','impact'
];
const TACTIC_LABELS = {
  'reconnaissance':'Reconnaissance','resource-development':'Resource Development','initial-access':'Initial Access',
  'execution':'Execution','persistence':'Persistence','privilege-escalation':'Privilege Escalation',
  'stealth':'Stealth','defense-impairment':'Defense Impairment','defense-evasion':'Defense Evasion',
  'credential-access':'Credential Access','discovery':'Discovery','lateral-movement':'Lateral Movement',
  'collection':'Collection','command-and-control':'Command and Control','exfiltration':'Exfiltration','impact':'Impact'
};

const DEFENSIVE_LENSES = [
  {key:'entry',label:'Entry & Preparation',tactics:['reconnaissance','resource-development','initial-access'],hint:'Reconnaissance · Resource Development · Initial Access'},
  {key:'execution',label:'Execution & Persistence',tactics:['execution','persistence'],hint:'Execution · Persistence'},
  {key:'identity',label:'Identity & Privilege',tactics:['credential-access','privilege-escalation'],hint:'Credential Access · Privilege Escalation'},
  {key:'defense',label:'Stealth & Defense',tactics:['stealth','defense-impairment','defense-evasion'],hint:'Stealth · Defense Impairment · Defense Evasion'},
  {key:'movement',label:'Discovery & Movement',tactics:['discovery','lateral-movement'],hint:'Discovery · Lateral Movement'},
  {key:'data',label:'Data, C2 & Impact',tactics:['collection','command-and-control','exfiltration','impact'],hint:'Collection · Command and Control · Exfiltration · Impact'}
];

const LEGACY_SCOPE_STORE_KEY = 'peridotan-investigation-scopes-v1';
const ENV_VIEW_STORE_KEY = 'peridotan-environment-views-v1';

// Investigation Lens = how to read ATT&CK for this question. It does NOT depend on My Environment.
// "curated" means the grouping is defined by this dashboard and is not a MITRE ATT&CK classification.
const INVESTIGATION_LENSES = {
  general:{label:'General',kind:'general',help:'テーマで絞らずATT&CK Evidence全体を見る'},
  identity:{label:'Identity',kind:'curated',tactics:['credential-access','privilege-escalation'],help:'Credential Access / Privilege Escalationを中心に見る'},
  internet:{label:'Internet-facing',kind:'curated',tactics:['initial-access','command-and-control'],platforms:['Network Devices','SaaS','IaaS'],help:'Initial Access / C2と外部公開系Platformを中心に見る'},
  virtualization:{label:'Virtualization',kind:'attck-native',platforms:['ESXi'],help:'ATT&CK Platform: ESXiを直接見る'},
  server:{label:'Server',kind:'curated',platforms:['Windows','Linux','ESXi'],help:'Windows / Linux / ESXiをサーバー観点でまとめて見る'},
  cloud:{label:'Cloud',kind:'curated',platforms:['IaaS','SaaS','Containers'],help:'IaaS / SaaS / Containersをクラウド観点でまとめて見る'}
};

// Environment Overlay = optional personalization. These are saved views over the shared Environment Profile.
const ENVIRONMENT_VIEWS = {
  none:{label:'Not used',mode:'none'},
  all:{label:'All My Environment',mode:'all'},
  identity:{label:'Identity Environment',mode:'saved'},
  internet:{label:'Internet-facing Environment',mode:'saved'},
  virtualization:{label:'Virtualization Environment',mode:'saved'},
  server:{label:'Server Environment',mode:'saved'},
  cloud:{label:'Cloud Environment',mode:'saved'},
  custom:{label:'Custom Environment',mode:'custom'}
};

// STEP 1 is search-first. Category selection narrows resolution but is not required.
const INVESTIGATION_SEARCH_SCOPES = {
  all:{label:'All',views:['actors','software','techniques'],includePlatforms:true},
  actors:{label:'Threat Actor',views:['actors'],includePlatforms:false},
  software:{label:'Software',views:['software'],includePlatforms:false},
  technology:{label:'Technique / Platform',views:['techniques','software'],includePlatforms:true}
};

// Name-based templates are suggestions only for saved Environment Views.
const ENV_VIEW_TEMPLATES = {
  identity:{platforms:['Identity Provider'],products:['entra','active directory','microsoft 365','office 365','okta','auth0','ping identity','adfs'],technologies:['entra','active directory','microsoft 365','office 365','powershell']},
  internet:{platforms:['Network Devices','SaaS','IaaS'],products:['fortinet','fortios','palo alto','pan-os','citrix','cisco','f5','cloudflare','zscaler','netskope'],technologies:['vpn','firewall','proxy','remote access']},
  virtualization:{platforms:['ESXi'],products:['vmware','esxi','vcenter','hyper-v','virtualbox'],technologies:['vmware','esxi','vcenter','hyper-v']},
  server:{platforms:['Windows','Linux','ESXi'],products:['windows server','red hat','ubuntu','linux','vmware','esxi'],technologies:['powershell','ssh']},
  cloud:{platforms:['IaaS','SaaS','Containers'],products:['aws','azure','google cloud','gcp','kubernetes','docker','microsoft 365'],technologies:['aws','azure','entra','kubernetes','container']}
};

function emptyScopeItems(){return {platforms:[],products:[],technologies:[]};}
function defaultEnvironmentViewStore(){
  const views={};
  for(const [key,def] of Object.entries(ENVIRONMENT_VIEWS)) if(def.mode==='saved') views[key]={label:def.label,items:emptyScopeItems()};
  return {schema_version:'1.0',updated_at:null,views};
}
function normalizeStoredItems(saved={}){
  return {platforms:[...(saved.platforms||[])],products:[...(saved.products||[])],technologies:[...(saved.technologies||[])]};
}
function loadEnvironmentViewStore(){
  const base=defaultEnvironmentViewStore();
  try{
    let raw=JSON.parse(localStorage.getItem(ENV_VIEW_STORE_KEY)||'null');
    // One-way compatibility read: preserve existing v0.6/v0.7 user-defined scopes as Environment Views.
    if(!raw||typeof raw!=='object'){
      const legacy=JSON.parse(localStorage.getItem(LEGACY_SCOPE_STORE_KEY)||'null');
      if(legacy&&typeof legacy==='object') raw={updated_at:legacy.updated_at,views:legacy.scopes||{}};
    }
    if(!raw||typeof raw!=='object')return base;
    for(const key of Object.keys(base.views)){
      const saved=raw.views?.[key]?.items||raw.scopes?.[key]?.items||{};
      base.views[key]={label:ENVIRONMENT_VIEWS[key].label,items:normalizeStoredItems(saved)};
    }
    base.updated_at=raw.updated_at||null;
    return base;
  }catch{return base;}
}
let environmentViewStore=loadEnvironmentViewStore();

function defaultInvestigation(){return {entry:'actors',searchScope:'all',resolvedTarget:null,query:'',lensKey:'general',overlayKey:'none',custom:emptyScopeItems(),started:false,result:null};}
function loadInvestigation(){
  try{
    const raw=JSON.parse(localStorage.getItem(INVESTIGATION_KEY)||'null');
    const base=defaultInvestigation();
    if(!raw||typeof raw!=='object')return base;
    const legacyLens=(raw.scopeKey&&INVESTIGATION_LENSES[raw.scopeKey])?raw.scopeKey:'general';
    const next={...base,...raw,custom:{...base.custom,...(raw.custom||{})}};
    if(!raw.lensKey)next.lensKey=legacyLens;
    if(!raw.searchScope)next.searchScope='all';
    if(!INVESTIGATION_SEARCH_SCOPES[next.searchScope])next.searchScope='all';
    if(!raw.overlayKey)next.overlayKey='none';
    if(!INVESTIGATION_LENSES[next.lensKey])next.lensKey='general';
    if(!ENVIRONMENT_VIEWS[next.overlayKey])next.overlayKey='none';
    if(next.entry==='vulnerability'){next.entry='actors';next.query='';next.resolvedTarget=null;next.started=false;next.result=null;}
    return next;
  }catch{return defaultInvestigation();}
}
function saveInvestigation(){try{localStorage.setItem(INVESTIGATION_KEY,JSON.stringify(investigation));}catch{} renderInvestigationWorkflow(); renderInvestigationResult(); renderExplorer();}
function saveEnvironmentViewStore(){environmentViewStore.updated_at=new Date().toISOString();try{localStorage.setItem(ENV_VIEW_STORE_KEY,JSON.stringify(environmentViewStore));}catch{} investigation.started=false; investigation.result=null; persistInvestigation(); renderInvestigationWorkflow();renderInvestigationResult();renderExplorer();}
function productScopeKey(row){return `${normalize(row?.vendor)}|${normalize(row?.product||'')}`;}
function itemCount(env){return (env.platforms||[]).length+(env.products||[]).length+(env.technologies||[]).length;}
function includesTerm(value,terms=[]){const q=normalize(value);return terms.some(t=>q.includes(normalize(t)));}
function exactScopeFromSelection(selection){
  const src={platforms:[...(environment.platforms||[])],products:[...(environment.products||[])],technologies:[...(environment.technologies||[])]};
  const chosen=selection||emptyScopeItems();
  return {
    platforms:src.platforms.filter(x=>(chosen.platforms||[]).some(v=>normalize(v)===normalize(x))),
    products:src.products.filter(x=>(chosen.products||[]).includes(productScopeKey(x))),
    technologies:src.technologies.filter(x=>(chosen.technologies||[]).some(v=>normalize(v)===normalize(x)))
  };
}
function environmentViewSelection(key=investigation.overlayKey){
  if(key==='custom')return investigation.custom||emptyScopeItems();
  if(ENVIRONMENT_VIEWS[key]?.mode==='saved')return environmentViewStore.views?.[key]?.items||emptyScopeItems();
  return emptyScopeItems();
}
function environmentOverlay(key=investigation.overlayKey){
  const src={platforms:[...(environment.platforms||[])],products:[...(environment.products||[])],technologies:[...(environment.technologies||[])]};
  if(key==='none')return emptyScopeItems();
  if(key==='all')return src;
  return exactScopeFromSelection(environmentViewSelection(key));
}
function templateCandidateScope(key){
  const rule=ENV_VIEW_TEMPLATES[key]; if(!rule)return emptyScopeItems();
  const src={platforms:[...(environment.platforms||[])],products:[...(environment.products||[])],technologies:[...(environment.technologies||[])]};
  return {
    platforms:src.platforms.filter(x=>(rule.platforms||[]).some(v=>normalize(v)===normalize(x))),
    products:src.products.filter(x=>includesTerm(`${x.vendor} ${x.product||''}`,rule.products||[])).map(productScopeKey),
    technologies:src.technologies.filter(x=>includesTerm(x,rule.technologies||[]))
  };
}
function lensLabel(key=investigation.lensKey){return INVESTIGATION_LENSES[key]?.label||'General';}
function overlayLabel(key=investigation.overlayKey){return ENVIRONMENT_VIEWS[key]?.label||'Not used';}
function scopeItemLabels(env){
  return [
    ...(env.platforms||[]).map(x=>`Platform: ${x}`),
    ...(env.products||[]).map(x=>`${x.vendor}${x.product?` / ${x.product}`:' / All products'}`),
    ...(env.technologies||[]).map(x=>`Technology: ${x}`)
  ];
}
const $ = (id) => document.getElementById(id);
const esc = (value='') => String(value).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
const fmtDate = (value) => value ? value.slice(0,10) : '—';
const uniq = (xs) => [...new Set((xs || []).filter(Boolean))];
const normalize = (value='') => String(value).trim().toLowerCase().replace(/\s+/g,' ');
const tacticLabel = (value) => TACTIC_LABELS[value] || String(value || '').split('-').map(x=>x.charAt(0).toUpperCase()+x.slice(1)).join(' ');

function entityLabel(view, id) {
  const obj = lookups[view]?.get(id);
  return obj ? `${obj.external_id || ''} ${obj.name}`.trim() : id;
}

function buildLookups(data) {
  for (const view of VIEWS) {
    lookups[view].clear();
    for (const item of data[view] || []) lookups[view].set(item.external_id, item);
  }
}

function relatedTechniques(item, view) {
  if (view === 'techniques') return [item];
  return (item.techniques || []).map(id => lookups.techniques.get(id)).filter(Boolean);
}

function matchesContext(item, view) {
  if (state.tactic) {
    const techs = relatedTechniques(item, view);
    if (!techs.some(t => (t.tactics || []).includes(state.tactic))) return false;
  }
  if (state.platform) {
    const target=normalize(state.platform);
    if (view === 'software' && (item.platforms || []).some(p=>normalize(p)===target)) {
      // direct Software platform match is sufficient
    } else if ((view === 'actors' || view === 'campaigns') && entityObservedPlatforms(item,view).some(p=>normalize(p)===target)) {
      // Actor / Campaign platform context is derived only from their ATT&CK-linked Technique / Software metadata.
    } else {
      const techs = relatedTechniques(item, view);
      if (!techs.some(t => (t.platforms || []).some(p=>normalize(p)===target))) return false;
    }
  }
  return true;
}

function searchText(item, view) {
  const related = [];
  if (view === 'actors') {
    related.push(...(item.techniques || []).map(id => entityLabel('techniques', id)));
    related.push(...(item.software || []).map(id => entityLabel('software', id)));
    related.push(...(item.campaigns || []).map(id => entityLabel('campaigns', id)));
  } else if (view === 'techniques') {
    related.push(...(item.actors || []).map(id => entityLabel('actors', id)));
    related.push(...(item.software || []).map(id => entityLabel('software', id)));
    related.push(...(item.campaigns || []).map(id => entityLabel('campaigns', id)));
  } else if (view === 'software') {
    related.push(...(item.actors || []).map(id => entityLabel('actors', id)));
    related.push(...(item.techniques || []).map(id => entityLabel('techniques', id)));
    related.push(...(item.campaigns || []).map(id => entityLabel('campaigns', id)));
  } else if (view === 'campaigns') {
    related.push(...(item.actors || []).map(id => entityLabel('actors', id)));
    related.push(...(item.techniques || []).map(id => entityLabel('techniques', id)));
    related.push(...(item.software || []).map(id => entityLabel('software', id)));
  }
  return [item.external_id,item.name,...(item.aliases||[]),item.description,...related].join(' ').toLowerCase();
}

function filteredItems() {
  const items = state.data?.[state.view] || [];
  const q = state.search.trim();
  if (!q) return items.filter(item => matchesContext(item,state.view));

  const anchors = primaryDirectMatches(q);
  return items.filter(item => {
    let matched = false;
    if (anchors.length) {
      // Direct matches are rendered in the Entity-aware Search panel.
      // The selected-tab list is reserved for ATT&CK relationship results only.
      matched = Boolean(relationshipContext(item,state.view,anchors));
    } else {
      // No direct Entity match: fall back to broad text/relationship search.
      matched = searchText(item,state.view).includes(q.toLowerCase());
    }
    return matched && matchesContext(item,state.view);
  });
}

function renderMeta() {
  const meta = state.data.meta || {};
  $('load-status').textContent = meta.placeholder ? 'データ未生成 — update scriptを実行してください' : 'MITRE ATT&CK Enterprise data loaded';
  const version = meta.collection_version || meta.attack_spec_version || 'latest';
  $('data-meta').textContent = `ATT&CK ${version} · Generated ${fmtDate(meta.generated_at)}`;
  if (meta.placeholder) {
    $('data-warning').hidden = false;
    $('data-warning').innerHTML = '<strong>初期データはまだ生成されていません。</strong><span><code>python scripts/update_attack.py</code> を実行すると、MITRE ATT&CKの最新データから dashboard.json を生成します。</span>';
  } else if (meta.schema_version !== '0.2.0') {
    $('data-warning').hidden = false;
    $('data-warning').innerHTML = '<strong>データスキーマが旧版です。</strong><span>v0.2のSoftware ⇄ Technique ⇄ Campaign横断関係を利用するため、<code>python scripts/update_attack.py</code> を再実行してください。</span>';
  }
}

function renderKpis() {
  const d = state.data;
  $('kpi-actors').textContent = (d.actors||[]).length.toLocaleString();
  const linkedTech = new Set((d.actors||[]).flatMap(a => a.techniques||[]));
  const linkedSoft = new Set((d.actors||[]).flatMap(a => a.software||[]));
  $('kpi-techniques').textContent = linkedTech.size.toLocaleString();
  $('kpi-software').textContent = linkedSoft.size.toLocaleString();
  $('kpi-campaigns').textContent = (d.campaigns||[]).length.toLocaleString();
}

function barRows(items, kind) {
  if (!items.length) return '<div class="empty">データなし</div>';
  const max = Math.max(...items.map(x => x.value),1);
  return items.map(x => `<button class="bar-row ${kind}" data-focus-view="${kind === 'technique' ? 'techniques':'actors'}" data-focus-id="${esc(x.external_id)}"><span class="bar-label">${esc(x.label)}</span><span class="bar-track"><span class="bar-fill" style="width:${Math.max(2,(x.value/max)*100)}%"></span></span><span class="bar-value">${x.value}</span></button>`).join('');
}

function renderPanels() {
  const topActors = [...(state.data.actors||[])].sort((a,b)=>(b.techniques?.length||0)-(a.techniques?.length||0)).slice(0,10).map(a=>({external_id:a.external_id,label:a.name,value:a.techniques?.length||0}));
  const actorCounts = new Map();
  for (const actor of state.data.actors||[]) for (const tid of actor.techniques||[]) actorCounts.set(tid,(actorCounts.get(tid)||0)+1);
  const topTechniques = [...actorCounts.entries()].map(([id,value])=>({external_id:id,label:entityLabel('techniques',id),value})).sort((a,b)=>b.value-a.value).slice(0,10);
  $('top-actors').innerHTML = barRows(topActors,'actor');
  $('top-techniques').innerHTML = barRows(topTechniques,'technique');
}

function populateFilters() {
  const tactics = uniq((state.data.techniques||[]).flatMap(t=>t.tactics||[])).sort((a,b)=>{
    const ai=TACTIC_ORDER.indexOf(a), bi=TACTIC_ORDER.indexOf(b);
    if (ai !== -1 || bi !== -1) return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi);
    return a.localeCompare(b);
  });
  const platforms = uniq([
    ...(state.data.techniques||[]).flatMap(t=>t.platforms||[]),
    ...(state.data.software||[]).flatMap(s=>s.platforms||[])
  ]).sort();
  $('tactic-filter').innerHTML = '<option value="">All tactics</option>' + tactics.map(v=>`<option value="${esc(v)}">${esc(tacticLabel(v))}</option>`).join('');
  $('platform-filter').innerHTML = '<option value="">All platforms</option>' + platforms.map(v=>`<option value="${esc(v)}">${esc(v)}</option>`).join('');
}

function syncControls() {
  $('search').value = state.search;
  $('tactic-filter').value = state.tactic;
  $('platform-filter').value = state.platform;
}

function renderActiveContext() {
  const parts = [];
  if (state.search) parts.push(`<span class="context-chip">Search: <b>${esc(state.search)}</b></span>`);
  if (state.tactic) parts.push(`<span class="context-chip">Tactic: <b>${esc(tacticLabel(state.tactic))}</b></span>`);
  if (state.platform) parts.push(`<span class="context-chip">Platform: <b>${esc(state.platform)}</b></span>`);
  if (state.focusOnly && state.focusId) parts.push(`<span class="context-chip focused-context">Focused profile: <b>${esc(entityLabel(state.view,state.focusId))}</b></span>`);
  const box = $('active-context');
  if (!parts.length) { box.hidden = true; box.innerHTML = ''; return; }
  box.hidden = false;
  box.innerHTML = `<strong>Active context</strong>${parts.join('')}<button type="button" id="clear-context" class="text-btn">すべて解除</button>`;
}

function directMatchScore(item, q) {
  const query = normalize(q);
  if (!query) return 0;
  const id = normalize(item.external_id);
  const name = normalize(item.name);
  const aliases = (item.aliases || []).map(normalize);
  if (query === name) return 140;
  if (query === id) return 135;
  if (aliases.includes(query)) return 130;
  if (name.startsWith(query)) return 100;
  if (id.startsWith(query)) return 95;
  if (aliases.some(a => a.startsWith(query))) return 90;
  if (name.includes(query)) return 75;
  if (id.includes(query)) return 70;
  if (aliases.some(a => a.includes(query))) return 65;
  return 0;
}

function directMatchBasis(item, q) {
  const query = normalize(q);
  if (!query) return '';
  const id = normalize(item.external_id);
  const name = normalize(item.name);
  const aliases = (item.aliases || []).map(normalize);
  if (query === name) return 'name exact';
  if (query === id) return 'ID exact';
  if (aliases.includes(query)) return 'alias exact';
  if (name.startsWith(query)) return 'name prefix';
  if (id.startsWith(query)) return 'ID prefix';
  if (aliases.some(a => a.startsWith(query))) return 'alias prefix';
  if (name.includes(query)) return 'name contains';
  if (id.includes(query)) return 'ID contains';
  if (aliases.some(a => a.includes(query))) return 'alias contains';
  return 'ID / name / alias';
}

function directMatches(q) {
  const matches = [];
  if (!normalize(q)) return matches;
  for (const view of VIEWS) {
    for (const item of state.data?.[view] || []) {
      const score = directMatchScore(item,q);
      if (score) matches.push({view,item,score});
    }
  }
  return matches.sort((a,b)=>b.score-a.score || a.item.name.localeCompare(b.item.name)).slice(0,12);
}

function relatedActorIds(view, item) {
  if (view === 'actors') return [item.external_id];
  if (item.actors?.length) return item.actors;
  if (view === 'techniques') return (state.data.actors||[]).filter(a=>(a.techniques||[]).includes(item.external_id)).map(a=>a.external_id);
  if (view === 'software') return (state.data.actors||[]).filter(a=>(a.software||[]).includes(item.external_id)).map(a=>a.external_id);
  if (view === 'campaigns') return (state.data.actors||[]).filter(a=>(a.campaigns||[]).includes(item.external_id)).map(a=>a.external_id);
  return [];
}

function relationshipReason(view,item) {
  const label = `${item.external_id} ${item.name}`;
  if (view === 'techniques') return `Uses technique: ${label}`;
  if (view === 'software') return `Uses software: ${label}`;
  if (view === 'campaigns') return `Attributed campaign: ${label}`;
  return `Direct actor match: ${label}`;
}

function matchMeta(view,item) {
  if (view === 'actors') return `${(item.aliases||[]).length} aliases · ${(item.techniques||[]).length} techniques`;
  if (view === 'techniques') return `${(item.tactics||[]).map(tacticLabel).join(' · ') || 'No tactic'} · ${(item.actors||[]).length} actors`;
  if (view === 'software') return `${item.software_type || 'software'}${(item.platforms||[]).length ? ' · '+item.platforms.slice(0,3).join(' / ') : ''} · ${(item.actors||[]).length} actors`;
  if (view === 'campaigns') return `${(item.actors||[]).length} actors · ${(item.techniques||[]).length} techniques · ${(item.software||[]).length} software`;
  return '';
}

function matchCard(match, primary=false) {
  const {view,item} = match;
  const basis = directMatchBasis(item, state.search);
  return `<button class="search-match-card ${view} ${primary?'primary':''}" data-focus-view="${view}" data-focus-id="${esc(item.external_id)}">
    <span class="match-type">${esc(VIEW_LABELS[view])}</span>
    <strong>${esc(item.external_id)} · ${esc(item.name)}</strong>
    <span class="evidence-badge direct">DIRECT MATCH · ${esc(basis)}</span>
    <small>${esc(matchMeta(view,item))}</small>
    <i>Open ${esc(VIEW_LABELS[view])} →</i>
  </button>`;
}

function primaryDirectMatches(q) {
  const matches = directMatches(q);
  if (!matches.length) return [];
  const topScore = matches[0].score;
  return matches.filter(m => m.score === topScore).slice(0,4);
}

function relationshipContext(item, view, suppliedAnchors=null) {
  const q = state.search.trim();
  if (!q) return '';

  const anchors = suppliedAnchors || primaryDirectMatches(q);
  for (const match of anchors) {
    const id = match.item.external_id;
    const label = `${id} ${match.item.name}`;

    if (view === 'actors') {
      if (match.view === 'techniques' && (item.techniques || []).includes(id)) return `Uses technique: ${label}`;
      if (match.view === 'software' && (item.software || []).includes(id)) return `Uses software: ${label}`;
      if (match.view === 'campaigns' && (item.campaigns || []).includes(id)) return `Attributed campaign: ${label}`;
    } else if (view === 'techniques') {
      if (match.view === 'actors' && (item.actors || []).includes(id)) return `Used by actor: ${label}`;
      if (match.view === 'software' && (item.software || []).includes(id)) return `Associated with software: ${label}`;
      if (match.view === 'campaigns' && (item.campaigns || []).includes(id)) return `Observed in campaign: ${label}`;
    } else if (view === 'software') {
      if (match.view === 'actors' && (item.actors || []).includes(id)) return `Used by actor: ${label}`;
      if (match.view === 'techniques' && (item.techniques || []).includes(id)) return `Uses technique: ${label}`;
      if (match.view === 'campaigns' && (item.campaigns || []).includes(id)) return `Observed in campaign: ${label}`;
    } else if (view === 'campaigns') {
      if (match.view === 'actors' && (item.actors || []).includes(id)) return `Attributed to actor: ${label}`;
      if (match.view === 'techniques' && (item.techniques || []).includes(id)) return `Uses technique: ${label}`;
      if (match.view === 'software' && (item.software || []).includes(id)) return `Uses software: ${label}`;
    }
  }
  return '';
}

function relationContext(item, view, suppliedAnchors=null) {
  return relationshipContext(item, view, suppliedAnchors);
}

function relationContextHtml(item, view) {
  const context = relationContext(item, view);
  return context ? `<small class="relation-context"><span class="evidence-badge relationship">ATT&amp;CK RELATIONSHIP</span><span>${esc(context)}</span></small>` : '';
}

function relatedListHeading() {
  const q = state.search.trim();
  if (!q) return '';
  const anchors = primaryDirectMatches(q);
  if (!anchors.length) return '';

  const targetLabel = VIEW_TITLES[state.view];
  let title;
  let note;

  if (anchors.length === 1) {
    const anchor = anchors[0];
    if (anchor.view === state.view) {
      title = `Additional ${targetLabel} related to ${anchor.item.name}`;
      note = `Primary Matchは上のDirect Matchにのみ表示します。ここでは${anchor.item.external_id} ${anchor.item.name}からATT&CKの直接Relationshipで辿れる追加Entityだけを表示します。`;
    } else {
      title = `Related ${targetLabel} for ${anchor.item.name}`;
      note = `${anchor.item.external_id} ${anchor.item.name} からATT&CKの直接Relationshipを辿った結果です。`;
    }
  } else {
    title = `Related ${targetLabel} for “${q}”`;
    note = '複数のPrimary MatchからATT&CKの直接Relationshipを辿った結果です。Direct Match自体はこの一覧には重複表示しません。';
  }

  return `<div class="related-list-heading"><div><p class="detail-kicker">ATT&amp;CK RELATIONSHIP · ${esc(targetLabel.toUpperCase())}</p><h3>${esc(title)}</h3><p>${esc(note)}</p></div></div>`;
}

function renderSearchInsight() {
  const box = $('search-insight');
  const q = state.search.trim();
  if (!q) { box.hidden = true; box.innerHTML = ''; return; }
  const matches = directMatches(q);
  if (!matches.length) { box.hidden = true; box.innerHTML = ''; return; }

  const topScore = matches[0].score;
  const primary = matches.filter(m=>m.score===topScore).slice(0,4);
  const other = matches.filter(m=>m.score!==topScore).slice(0,6);

  const directActorIds = new Set(matches.filter(m=>m.view==='actors').map(m=>m.item.external_id));
  const actorReasons = new Map();
  for (const match of matches.slice(0,8)) {
    if (match.view === 'actors') continue;
    for (const aid of relatedActorIds(match.view,match.item)) {
      if (directActorIds.has(aid)) continue;
      if (!actorReasons.has(aid)) actorReasons.set(aid, []);
      actorReasons.get(aid).push(relationshipReason(match.view,match.item));
    }
  }
  const relatedActors = [...actorReasons.entries()]
    .map(([id,reasons])=>({actor:lookups.actors.get(id),reasons:uniq(reasons)}))
    .filter(x=>x.actor)
    .sort((a,b)=>b.reasons.length-a.reasons.length || a.actor.name.localeCompare(b.actor.name));

  box.hidden = false;
  box.innerHTML = `<div class="search-insight-heading"><div><p class="detail-kicker">ENTITY-AWARE SEARCH</p><h3>Direct matches for “${esc(q)}”</h3></div><span>全Entityを横断</span></div>
    <div class="search-section"><strong>${primary.length===1?'Primary match':'Primary matches'}</strong><div class="search-match-grid">${primary.map(m=>matchCard(m,true)).join('')}</div></div>
    ${other.length?`<div class="search-section"><strong>Other direct matches</strong><div class="search-match-grid compact">${other.map(m=>matchCard(m,false)).join('')}</div></div>`:''}
    ${relatedActors.length?`<div class="search-section"><div class="detail-heading-row"><strong>Related Threat Actors</strong><span>${relatedActors.length} actors</span></div><div class="related-actor-grid">${relatedActors.slice(0,12).map(x=>`<button class="related-actor-card" data-focus-view="actors" data-focus-id="${esc(x.actor.external_id)}"><b>${esc(x.actor.external_id)} · ${esc(x.actor.name)}</b><span class="evidence-badge relationship">ATT&amp;CK RELATIONSHIP</span><small>${esc(x.reasons.slice(0,2).join(' / '))}</small></button>`).join('')}</div>${relatedActors.length>12?`<p class="micro-note">関連Actorは上位12件を表示しています。ActorsタブではATT&CK Relationshipで辿れる全件を確認できます。</p>`:''}</div>`:''}
    <div class="search-evidence-note"><span><b>DIRECT MATCH</b> = ATT&amp;CK ID / name / alias の一致</span><span><b>ATT&amp;CK RELATIONSHIP</b> = 現在のATT&amp;CKデータに記録された直接関係</span><span>共通Techniqueなどから推定するDerived / analytical relationshipは表示していません。</span></div>`;
}

function chips(ids, view, max=16) {
  if (!ids?.length) return '<span class="muted">None recorded</span>';
  const shown = ids.slice(0,max);
  const hidden = ids.slice(max);
  const html = shown.map(id=>`<button class="chip" data-focus-view="${view}" data-focus-id="${esc(id)}">${esc(entityLabel(view,id))}</button>`).join('');
  if (!hidden.length) return html;
  const overflow = hidden.map(id=>`<button class="chip" data-focus-view="${view}" data-focus-id="${esc(id)}">${esc(entityLabel(view,id))}</button>`).join('');
  return `${html}<span class="chip-overflow" data-chip-overflow hidden>${overflow}</span><button type="button" class="chip chip-more" data-expand-chips aria-expanded="false" data-more-label="+${hidden.length} more">+${hidden.length} more</button>`;
}

function aliasChips(aliases) {
  if (!aliases?.length) return '<span class="muted">None recorded</span>';
  return aliases.map(x=>`<span class="chip alias-chip">${esc(x)}</span>`).join('');
}

function actorAliases(actor) {
  const actorName = normalize(actor?.name);
  return uniq((actor?.aliases || []).filter(alias => normalize(alias) !== actorName));
}

function actorTacticGroups(actor) {
  const groups = new Map();
  for (const id of actor.techniques || []) {
    const tech = lookups.techniques.get(id);
    if (!tech) continue;
    for (const tactic of tech.tactics || []) {
      if (!groups.has(tactic)) groups.set(tactic, []);
      groups.get(tactic).push(tech);
    }
  }
  return [...groups.entries()]
    .map(([tactic, techniques])=>({tactic, techniques: techniques.sort((a,b)=>a.external_id.localeCompare(b.external_id))}))
    .sort((a,b)=>{
      const ai=TACTIC_ORDER.indexOf(a.tactic), bi=TACTIC_ORDER.indexOf(b.tactic);
      if (ai !== -1 || bi !== -1) return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi);
      return a.tactic.localeCompare(b.tactic);
    });
}

function actorTacticCoverage(actor) {
  const groups = actorTacticGroups(actor);
  if (!groups.length) return '<div class="empty compact-empty">No tactic relationships recorded.</div>';
  return `<div class="tactic-grid">${groups.map(g=>`<button class="tactic-card" type="button" data-open-tactic="${esc(g.tactic)}" aria-label="Open ${esc(tacticLabel(g.tactic))} techniques"><span>${esc(tacticLabel(g.tactic))}</span><b>${g.techniques.length}</b><small>details ↓</small></button>`).join('')}</div>`;
}

function actorPlatforms(actor) {
  const platforms = [];
  for (const id of actor.techniques || []) {
    const tech = lookups.techniques.get(id);
    if (tech) platforms.push(...(tech.platforms || []));
  }
  for (const id of actor.software || []) {
    const soft = lookups.software.get(id);
    if (soft) platforms.push(...(soft.platforms || []));
  }
  return uniq(platforms).sort((a,b)=>a.localeCompare(b));
}

function entityObservedPlatforms(item,view) {
  if (!item) return [];
  if (view === 'software' || view === 'techniques') return uniq(item.platforms || []).sort((a,b)=>a.localeCompare(b));
  if (view === 'actors') return actorPlatforms(item);
  if (view === 'campaigns') {
    const platforms=[];
    for (const id of item.techniques || []) { const tech=lookups.techniques.get(id); if(tech) platforms.push(...(tech.platforms||[])); }
    for (const id of item.software || []) { const soft=lookups.software.get(id); if(soft) platforms.push(...(soft.platforms||[])); }
    for (const id of item.actors || []) { const actor=lookups.actors.get(id); if(actor) platforms.push(...actorPlatforms(actor)); }
    return uniq(platforms).sort((a,b)=>a.localeCompare(b));
  }
  return [];
}

function canonicalPlatformForTechnologyQuery(query) {
  const q=normalize(query);
  if(!q)return '';
  const platforms=environmentPlatformOptions();
  const exact=platforms.find(p=>normalize(p)===q);
  if(exact)return exact;
  const aliases={
    'vmware esxi':'ESXi','vmware / esxi':'ESXi','esxi':'ESXi',
    'windows server':'Windows','microsoft windows':'Windows','windows':'Windows',
    'linux':'Linux','mac os':'macOS','macos':'macOS','android':'Android','ios':'iOS',
    'containers':'Containers','container':'Containers','saas':'SaaS','iaas':'IaaS',
    'network devices':'Network Devices','identity provider':'Identity Provider','office suite':'Office Suite'
  };
  const candidate=aliases[q]||'';
  if(candidate){
    const canonical=platforms.find(p=>normalize(p)===normalize(candidate));
    return canonical||candidate;
  }
  // If the query is a registered Vendor / Product, reuse the same conservative Product -> Platform normalization.
  for(const product of environment.products||[]){
    const labels=[product.product,`${product.vendor} ${product.product||''}`,`${product.vendor} / ${product.product||''}`].filter(Boolean);
    if(labels.some(v=>normalize(v)===q)){
      const cands=productPlatformCandidates(product);
      if(cands.length){const canonical=platforms.find(p=>normalize(p)===normalize(cands[0]));return canonical||cands[0];}
    }
  }
  return '';
}

function platformInvestigationRelated(platform) {
  const target=normalize(platform);
  const software=(state.data?.software||[]).filter(x=>(x.platforms||[]).some(p=>normalize(p)===target));
  const techniques=(state.data?.techniques||[]).filter(x=>(x.platforms||[]).some(p=>normalize(p)===target));
  const actors=(state.data?.actors||[]).filter(x=>actorPlatforms(x).some(p=>normalize(p)===target));
  const campaigns=(state.data?.campaigns||[]).filter(x=>entityObservedPlatforms(x,'campaigns').some(p=>normalize(p)===target));
  return {software,techniques,actors,campaigns};
}

function saveEnvironment(next) {
  environment = ENV_STORE ? ENV_STORE.save(next) : next;
  investigation.started=false; investigation.result=null; persistInvestigation();
  renderEnvironmentEditor();
  renderInvestigationWorkflow();
  renderInvestigationResult();
  renderExplorer();
}

function environmentPlatformOptions() {
  return uniq([
    ...(state.data?.techniques||[]).flatMap(t=>t.platforms||[]),
    ...(state.data?.software||[]).flatMap(s=>s.platforms||[])
  ]).sort((a,b)=>a.localeCompare(b));
}

function environmentProductCatalog() {
  const rows=ENV_STORE?.productCatalog?.()||[];
  const legacy=ENV_STORE?.readLegacyWatchlist?.()||[];
  const current=environment.products||[];
  const out=[];
  for(const row of [...rows,...legacy,...current]){
    if(!row?.vendor)continue;
    if(!out.some(x=>normalize(x.vendor)===normalize(row.vendor)&&normalize(x.product||'')===normalize(row.product||''))) out.push({vendor:row.vendor,product:row.product||''});
  }
  return out;
}

function populateEnvironmentProductSuggestions() {
  const vendorList=$('environment-vendor-suggestions'), productList=$('environment-product-suggestions');
  if(!vendorList||!productList)return;
  const catalog=environmentProductCatalog();
  vendorList.innerHTML=[...new Set(catalog.map(x=>x.vendor))].sort((a,b)=>a.localeCompare(b)).map(x=>`<option value="${esc(x)}"></option>`).join('');
  const vendor=normalize($('environment-vendor-input')?.value||'');
  const products=(vendor?catalog.filter(x=>normalize(x.vendor)===vendor):catalog).map(x=>x.product).filter(Boolean);
  productList.innerHTML=[...new Set(products)].sort((a,b)=>a.localeCompare(b)).map(x=>`<option value="${esc(x)}"></option>`).join('');
}

function renderEnvironmentProductSuggestion() {
  const box=$('environment-product-suggestion');
  if(!box||!ENV_STORE?.analyzeProduct)return;
  const vendor=$('environment-vendor-input')?.value||'', product=$('environment-product-input')?.value||'';
  const analysis=ENV_STORE.analyzeProduct(vendor,product);
  box.hidden=true; box.innerHTML=''; box.className='environment-product-suggestion';
  if(!vendor.trim())return;
  if((analysis.status==='canonical'||analysis.status==='canonical-vendor')&&analysis.canonical&&analysis.changed){
    box.hidden=false; box.classList.add('safe');
    box.innerHTML=`<div><strong>表記を正規化します</strong><span>追加時に <b>${esc(analysis.canonical.vendor)}${analysis.canonical.product?` / ${esc(analysis.canonical.product)}`:''}</b> として保存します。</span></div>`;
    return;
  }
  if(analysis.status==='vendor-mismatch'&&analysis.canonical){
    box.hidden=false; box.classList.add('warning');
    box.innerHTML=`<div><strong>Vendor / Product候補を確認してください</strong><span>Product <b>${esc(product)}</b> は既知候補では <b>${esc(analysis.canonical.vendor)} / ${esc(analysis.canonical.product)}</b> と一致します。現在のVendor <b>${esc(vendor)}</b> とは異なります。</span><small>候補は入力補助です。未知製品や独自表記は入力のまま追加できます。</small></div><button type="button" data-apply-environment-product-suggestion data-vendor="${esc(analysis.canonical.vendor)}" data-product="${esc(analysis.canonical.product)}">候補を使用</button>`;
    return;
  }
  if(analysis.status==='unknown'&&analysis.suggestions?.length){
    const top=analysis.suggestions.slice(0,3);
    box.hidden=false; box.classList.add('hint');
    box.innerHTML=`<div><strong>近い候補</strong><span>${top.map(x=>`${esc(x.vendor)} / ${esc(x.product)}`).join(' · ')}</span><small>候補にないVendor / Productもそのまま登録できます。</small></div>`;
  }
}

function renderEnvironmentEditor() {
  if (!$('environment-status')) return;
  const platforms=environment.platforms||[], products=environment.products||[], technologies=environment.technologies||[];
  $('env-platform-count').textContent=platforms.length.toLocaleString();
  $('env-product-count').textContent=products.length.toLocaleString();
  $('env-technology-count').textContent=technologies.length.toLocaleString();
  $('environment-status').textContent=`${(platforms.length+products.length+technologies.length).toLocaleString()} items`;
  const selected=new Set(platforms.map(normalize));
  $('environment-platforms').innerHTML=environmentPlatformOptions().map(p=>`<label class="environment-option"><input type="checkbox" data-environment-platform value="${esc(p)}" ${selected.has(normalize(p))?'checked':''}><span>${esc(p)}</span></label>`).join('')||'<span class="muted">Platform data not available.</span>';
  $('environment-products').innerHTML=products.map((row,i)=>`<span class="environment-chip"><b>${esc(row.vendor)}</b>${row.product?` <small>${esc(row.product)}</small>`:' <small>All products</small>'}<button type="button" data-remove-environment-product="${i}" aria-label="Remove ${esc(row.vendor)} ${esc(row.product||'')}">×</button></span>`).join('')||'<span class="environment-empty">Productはまだ登録されていません。</span>';
  const reviewBox=$('environment-product-review');
  if(reviewBox&&ENV_STORE?.analyzeProduct){
    const reviews=products.map((row,i)=>({i,row,analysis:ENV_STORE.analyzeProduct(row.vendor,row.product)})).filter(x=>x.analysis.status==='vendor-mismatch'&&x.analysis.canonical);
    reviewBox.hidden=!reviews.length;
    reviewBox.innerHTML=reviews.length?`<strong>Vendor / Product確認候補 ${reviews.length}件</strong>${reviews.map(x=>`<div><span>${esc(x.row.vendor)}${x.row.product?` / ${esc(x.row.product)}`:''}</span><b>→ ${esc(x.analysis.canonical.vendor)} / ${esc(x.analysis.canonical.product)}</b><button type="button" data-fix-environment-product="${x.i}" data-vendor="${esc(x.analysis.canonical.vendor)}" data-product="${esc(x.analysis.canonical.product)}">候補に修正</button></div>`).join('')}<small>Product名から一意に推定できる既知候補だけを表示しています。自動修正はしません。</small>`:'';
  }
  $('environment-technologies').innerHTML=technologies.map((name,i)=>`<span class="environment-chip"><span>${esc(name)}</span><button type="button" data-remove-environment-technology="${i}" aria-label="Remove ${esc(name)}">×</button></span>`).join('')||'<span class="environment-empty">Technologyはまだ登録されていません。</span>';
  populateEnvironmentProductSuggestions();
  renderEnvironmentProductSuggestion();
  const legacy=$('environment-legacy');
  const legacyRows=ENV_STORE?ENV_STORE.readLegacyWatchlist():[];
  const importable=legacyRows.filter(row=>!products.some(p=>normalize(p.vendor)===normalize(row.vendor)&&normalize(p.product)===normalize(row.product)));
  if(importable.length){
    const preview=importable.slice(0,4).map(row=>`${esc(row.vendor)}${row.product?` / ${esc(row.product)}`:''}`).join(' · ');
    legacy.hidden=false;
    legacy.innerHTML=`<div><strong>既存Vulnerability Watchlistを検出</strong><span>${importable.length}件を共通My EnvironmentのProductへ取り込めます。既知の表記は共通表記へ正規化します。</span>${preview?`<small>${preview}${importable.length>4?' · …':''}</small>`:''}<em>旧Watchlistは削除しません。</em></div><button type="button" id="environment-import-legacy">${importable.length}件を取り込む</button>`;
  } else {legacy.hidden=true;legacy.innerHTML='';}
}

function addEnvironmentProduct() {
  const vendor=$('environment-vendor-input').value.trim(), product=$('environment-product-input').value.trim();
  if(!vendor) return;
  const analysis=ENV_STORE?.analyzeProduct?.(vendor,product);
  const safeCanonical=analysis&&['canonical','canonical-vendor'].includes(analysis.status)&&analysis.canonical;
  const entry=safeCanonical?analysis.canonical:{vendor,product};
  const rows=[...(environment.products||[])];
  if(!rows.some(x=>normalize(x.vendor)===normalize(entry.vendor)&&normalize(x.product)===normalize(entry.product))) rows.push(entry);
  $('environment-vendor-input').value=''; $('environment-product-input').value='';
  saveEnvironment({...environment,products:rows});
}

function addEnvironmentTechnology() {
  const value=$('environment-technology-input').value.trim();
  if(!value) return;
  const rows=[...(environment.technologies||[])];
  if(!rows.some(x=>normalize(x)===normalize(value))) rows.push(value);
  $('environment-technology-input').value='';
  saveEnvironment({...environment,technologies:rows});
}

function technologyEntityMatches(actor, sourceEnvironment=environment) {
  const entities=[];
  for(const id of actor.techniques||[]){const x=lookups.techniques.get(id);if(x)entities.push({view:'techniques',item:x});}
  for(const id of actor.software||[]){const x=lookups.software.get(id);if(x)entities.push({view:'software',item:x});}
  const matched=[], unmatched=[];
  for(const techName of sourceEnvironment.technologies||[]){
    const q=normalize(techName);
    const hits=entities.filter(({item})=>[item.external_id,item.name,...(item.aliases||[])].some(v=>normalize(v)===q));
    if(hits.length) matched.push({technology:techName,hits}); else unmatched.push(techName);
  }
  return {matched,unmatched};
}

function vulnerabilityDashboardUrl(actor=null) {
  const params = new URLSearchParams();
  params.set('scope','my');
  if(actor){
    params.set('from','threat-actor');
    params.set('actor',actor.external_id||'');
    params.set('actorName',actor.name||'');
  }
  return `../vulnerability-intelligence-dashboard/?${params.toString()}`;
}

function deepLinkSourceLabel(value='') {
  const key=normalize(value).replace(/\s+/g,'-');
  if(key==='security-intelligence-library'||key==='security-library')return 'Security Intelligence Library';
  if(key==='vulnerability-intelligence'||key==='vulnerability-intelligence-dashboard')return 'Vulnerability Intelligence';
  return value || 'External context';
}

function parseEntityDeepLink(raw='') {
  const value=String(raw||'').trim();
  const split=value.indexOf(':');
  if(split<1)return null;
  const type=normalize(value.slice(0,split)).replace(/_/g,'-');
  const ref=value.slice(split+1).trim();
  if(!ref)return null;
  const aliases={
    actor:'actors','threat-actor':'actors',group:'actors',actors:'actors',
    software:'software',malware:'software',tool:'software',
    technique:'techniques',technology:'techniques',techniques:'techniques',
    campaign:'campaigns',campaigns:'campaigns',
    platform:'platform'
  };
  const target=aliases[type];
  return target?{type:target,ref}:null;
}

function exactEntityForDeepLink(view,ref) {
  const q=normalize(ref);
  return (state.data?.[view]||[]).find(item=>
    normalize(item.external_id)===q || normalize(item.name)===q || (item.aliases||[]).some(a=>normalize(a)===q)
  )||null;
}

function applyEntityDeepLink(raw='') {
  const parsed=parseEntityDeepLink(raw);
  if(!parsed)return false;

  // Campaign is currently a profile/explorer target rather than a STEP 3 investigation target.
  if(parsed.type==='campaigns'){
    const item=exactEntityForDeepLink('campaigns',parsed.ref);
    if(!item)return false;
    state.view='campaigns'; state.search=''; state.focusId=item.external_id; state.focusOnly=true;
    return true;
  }

  if(parsed.type==='platform'){
    const canonical=investigationPlatformValues().find(x=>normalize(x)===normalize(parsed.ref)) || canonicalPlatformForTechnologyQuery(parsed.ref);
    if(!canonical)return false;
    investigation.query=canonical;
    investigation.searchScope='technology';
    investigation.entry='technology';
    investigation.resolvedTarget={kind:'platform',platform:canonical};
    investigation.started=false;
    investigation.result=null;
    state.view='techniques'; state.search=''; state.focusId=''; state.focusOnly=false; state.platform=canonical;
    return true;
  }

  const item=exactEntityForDeepLink(parsed.type,parsed.ref);
  if(!item)return false;
  const scope=parsed.type==='actors'?'actors':parsed.type==='software'?'software':'technology';
  investigation.query=item.external_id || item.name;
  investigation.searchScope=scope;
  investigation.entry=parsed.type==='actors'?'actors':parsed.type==='software'?'software':'technology';
  investigation.resolvedTarget={kind:'entity',view:parsed.type,id:item.external_id};
  investigation.started=false;
  investigation.result=null;
  state.view=parsed.type; state.search=''; state.focusId=''; state.focusOnly=false; state.tactic=''; state.platform='';
  return true;
}

function renderExternalLaunchContext(){
  const box=$('external-launch-context');
  if(!box)return;
  if(!externalLaunchContext){box.hidden=true;box.innerHTML='';return;}
  const source=deepLinkSourceLabel(externalLaunchContext.from);
  const title=externalLaunchContext.title||externalLaunchContext.context||'';
  box.hidden=false;
  box.innerHTML=`<div><span>INTELLIGENCE CONTEXT</span><strong>Launched from ${esc(source)}</strong>${title?`<small>${esc(title)}</small>`:''}</div><p>この情報は調査入口のNavigation Contextです。ATT&amp;CK direct evidenceやrelationshipとしては扱いません。</p>`;
}

function applyLaunchParams() {
  const params=new URLSearchParams(window.location.search);

  // Legacy explorer deep links remain supported.
  const view=params.get('view');
  if(view&&['actors','techniques','software','campaigns'].includes(view)) state.view=view;
  if(params.has('q')) state.search=params.get('q')||'';
  if(params.has('focus')) state.focusId=params.get('focus')||'';
  if(params.has('tactic')) state.tactic=params.get('tactic')||'';
  if(params.has('platform')) state.platform=params.get('platform')||'';

  // v0.8 stable investigation deep-link contract.
  if(params.has('entity')) applyEntityDeepLink(params.get('entity')||'');
  const lens=params.get('lens');
  if(lens&&INVESTIGATION_LENSES[lens]) investigation.lensKey=lens;
  const overlay=params.get('overlay');
  if(overlay&&ENVIRONMENT_VIEWS[overlay]) investigation.overlayKey=overlay;

  const from=params.get('from')||'';
  const context=params.get('context')||'';
  const title=params.get('contextTitle')||'';
  externalLaunchContext=(from||context||title)?{from,context,title}:null;
  persistInvestigation();
}

function productPlatformCandidates(row){
  const p=normalize(row?.product||'');
  if(!p)return [];
  const candidates=[];
  if(p==='esxi'||p==='vmware esxi')candidates.push('ESXi');
  if(p==='windows'||p.startsWith('windows server'))candidates.push('Windows');
  if(p==='linux')candidates.push('Linux');
  if(p==='macos'||p==='mac os')candidates.push('macOS');
  if(p==='android')candidates.push('Android');
  if(p==='ios')candidates.push('iOS');
  return uniq(candidates);
}

function normalizedEnvironmentOverlaps(entity,view,sourceEnvironment=environmentOverlay()){
  const observedPlatforms=(view==='actors'||view==='campaigns')?actorPlatforms(entity):(entity.platforms||[]);
  const rows=[];
  for(const product of sourceEnvironment.products||[]){
    const productLabel=`${product.vendor}${product.product?` / ${product.product}`:' / All products'}`;
    for(const candidate of productPlatformCandidates(product)){
      const observed=observedPlatforms.find(x=>normalize(x)===normalize(candidate));
      if(observed)rows.push({productLabel,platform:observed,reason:'Product name → ATT&CK platform'});
    }
  }
  const seen=new Set();
  return rows.filter(row=>{const key=`${normalize(row.productLabel)}|${normalize(row.platform)}`;if(seen.has(key))return false;seen.add(key);return true;});
}

function entityObservedPlatforms(entity,view){
  return (view==='actors'||view==='campaigns')?actorPlatforms(entity):(entity.platforms||[]);
}
function entityRelatedTechniques(entity,view){
  if(view==='techniques')return [entity];
  return (entity.techniques||[]).map(id=>lookups.techniques.get(id)).filter(Boolean);
}
function lensStats(entity,view,lensKey=investigation.lensKey){
  const lens=INVESTIGATION_LENSES[lensKey]||INVESTIGATION_LENSES.general;
  const platforms=entityObservedPlatforms(entity,view);
  const techniques=entityRelatedTechniques(entity,view);
  if(lens.kind==='general')return {lens,platforms,techniques,platformMatches:[],techniqueMatches:[],matchCount:0};
  const platformMatches=(lens.platforms||[]).filter(p=>platforms.some(x=>normalize(x)===normalize(p)));
  const techniqueMatches=techniques.filter(t=>(t.tactics||[]).some(x=>(lens.tactics||[]).includes(x)));
  return {lens,platforms,techniques,platformMatches,techniqueMatches,matchCount:platformMatches.length+techniqueMatches.length};
}
function lensRelevanceHtml(entity,view){
  const stats=lensStats(entity,view);
  const lens=stats.lens;
  if(lens.kind==='general'){
    return `<div class="lens-relevance general-lens"><div class="lens-status-line"><span class="lens-type general">GENERAL</span><strong>テーマによる絞り込みなし</strong></div><p>General LensではATT&amp;CK Evidence全体をそのまま読みます。My Environmentの登録有無とは無関係です。</p></div>`;
  }
  const typeLabel=lens.kind==='attck-native'?'ATT&CK-NATIVE':'DASHBOARD-CURATED';
  const platformChips=stats.platformMatches.map(x=>`<span class="result-evidence-chip"><b>Platform</b>${esc(x)}</span>`);
  const techniqueChips=stats.techniqueMatches.slice(0,12).map(t=>`<button type="button" class="result-evidence-chip action" data-focus-view="techniques" data-focus-id="${esc(t.external_id)}"><b>${esc(t.external_id)}</b>${esc(t.name)}</button>`);
  return `<div class="lens-relevance">
    <div class="lens-status-line"><span class="lens-type ${lens.kind==='attck-native'?'native':'curated'}">${typeLabel}</span><strong>${stats.matchCount} observed match${stats.matchCount===1?'':'es'}</strong></div>
    <p>${esc(lens.help)}</p>
    ${(platformChips.length||techniqueChips.length)?`<div class="result-direct-evidence">${platformChips.join('')}${techniqueChips.join('')}</div>`:'<p class="semantic-empty">現在読み込んでいるATT&amp;CK metadataでは、このLens条件に合う接点を確認できません。</p>'}
    ${stats.techniqueMatches.length>12?`<p class="semantic-note">Technique matchは先頭12件を表示しています（全${stats.techniqueMatches.length}件）。</p>`:''}
    <p class="semantic-note">${lens.kind==='attck-native'?'このLensはATT&CK Platform metadataのexact matchを主条件にします。':'このLensのグルーピングは本ダッシュボード独自の閲覧補助です。MITRE ATT&CKの正式分類ではありません。'}</p>
  </div>`;
}

function investigationRelevance(actor) {
  const overlayMode=ENVIRONMENT_VIEWS[investigation.overlayKey]?.mode||'none';
  return `<section class="profile-context-strip">
    <span>INVESTIGATION CONTEXT</span>
    <strong>Lens: ${esc(lensLabel())}</strong>
    <em>Overlay: ${esc(overlayMode==='none'?'Not used':overlayLabel())}</em>
    <small>no risk score</small>
  </section>`;
}

function renderCustomScopeOptions(){
  const box=$('investigation-custom-options'); if(!box)return;
  const key=investigation.overlayKey;
  const editor=$('investigation-custom-editor');
  const label=$('investigation-scope-editor-label');
  const hint=$('investigation-scope-editor-hint');
  if(key==='none'||key==='all'){
    if(editor) editor.hidden=true;
    box.innerHTML='';
    return;
  }
  if(editor) editor.hidden=false;
  const selection=environmentViewSelection(key);
  const isSaved=ENVIRONMENT_VIEWS[key]?.mode==='saved';
  if(label) label.textContent=isSaved?`${overlayLabel(key)}を編集`:'Custom Environmentを編集';
  if(hint) hint.textContent='Environment Profileから今回重ねる項目を選択';
  const sections=[];
  const attr='data-environment-view-item';
  if((environment.platforms||[]).length) sections.push(`<div class="custom-scope-group"><strong>Platforms</strong><div>${(environment.platforms||[]).map(x=>`<label><input type="checkbox" ${attr}="platforms" value="${esc(x)}" ${(selection.platforms||[]).some(v=>normalize(v)===normalize(x))?'checked':''}><span>${esc(x)}</span></label>`).join('')}</div></div>`);
  if((environment.products||[]).length) sections.push(`<div class="custom-scope-group"><strong>Products</strong><div>${(environment.products||[]).map(x=>{const pkey=productScopeKey(x);const plabel=`${x.vendor}${x.product?` / ${x.product}`:' / All products'}`;return `<label><input type="checkbox" ${attr}="products" value="${esc(pkey)}" ${(selection.products||[]).includes(pkey)?'checked':''}><span>${esc(plabel)}</span></label>`;}).join('')}</div></div>`);
  if((environment.technologies||[]).length) sections.push(`<div class="custom-scope-group"><strong>Technologies</strong><div>${(environment.technologies||[]).map(x=>`<label><input type="checkbox" ${attr}="technologies" value="${esc(x)}" ${(selection.technologies||[]).some(v=>normalize(v)===normalize(x))?'checked':''}><span>${esc(x)}</span></label>`).join('')}</div></div>`);
  const candidate=isSaved?templateCandidateScope(key):emptyScopeItems();
  const candidateCount=(candidate.platforms||[]).length+(candidate.products||[]).length+(candidate.technologies||[]).length;
  const selectedCount=itemCount(exactScopeFromSelection(selection));
  const actions=`<div class="scope-editor-actions">${isSaved?`<button type="button" data-apply-scope-template="${esc(key)}" ${candidateCount?'':'disabled'}>候補を適用 (${candidateCount})</button>`:''}<button type="button" class="scope-clear-button" data-clear-scope="${esc(key)}">すべて解除</button><button type="button" class="scope-done-button" data-close-scope-editor>編集を閉じる</button></div>${isSaved?'<p class="scope-template-note">候補はEnvironment Viewを作るための名称ベース入力補助です。自動分類やThreat relevance判定ではありません。</p>':''}`;
  box.innerHTML=actions+(sections.join('')||'<span class="muted">Environment Profileが未登録です。OverlayなしでもInvestigationは実行できます。</span>');
}

function updateScopeItem(kind,value,checked){
  const key=investigation.overlayKey;
  const current={...environmentViewSelection(key),[kind]:[...(environmentViewSelection(key)?.[kind]||[])]};
  const rows=current[kind];
  const next=rows.filter(x=>kind==='products'?x!==value:normalize(x)!==normalize(value));
  if(checked)next.push(value);
  current[kind]=next;
  if(key==='custom'){
    investigation.custom={...(investigation.custom||{}),...current};
    saveInvestigation();
    return;
  }
  if(ENVIRONMENT_VIEWS[key]?.mode==='saved'){
    environmentViewStore.views[key]={label:overlayLabel(key),items:current};
    saveEnvironmentViewStore();
  }
}

function replaceScopeSelection(key,items){
  const next={platforms:[...(items.platforms||[])],products:[...(items.products||[])],technologies:[...(items.technologies||[])]};
  if(key==='custom'){
    investigation.custom=next;
    saveInvestigation();
    return;
  }
  if(ENVIRONMENT_VIEWS[key]?.mode==='saved'){
    environmentViewStore.views[key]={label:overlayLabel(key),items:next};
    saveEnvironmentViewStore();
  }
}

function currentFocusedEntity(){
  if(!state.focusId)return null;
  for(const view of VIEWS){const item=lookups[view]?.get(state.focusId);if(item)return {view,item};}
  return null;
}


function investigationSearchScope(){
  return INVESTIGATION_SEARCH_SCOPES[investigation.searchScope]||INVESTIGATION_SEARCH_SCOPES.all;
}

function investigationPlatformValues(){
  return uniq([
    ...(state.data?.techniques||[]).flatMap(x=>x.platforms||[]),
    ...(state.data?.software||[]).flatMap(x=>x.platforms||[])
  ]).sort((a,b)=>a.localeCompare(b));
}

function platformResolutionScore(platform,q){
  const query=normalize(q), name=normalize(platform);
  if(!query||!name)return 0;
  if(query===name)return 140;
  const canonical=canonicalPlatformForTechnologyQuery(q);
  if(canonical&&normalize(canonical)===name)return 132;
  if(name.startsWith(query))return 100;
  if(name.includes(query))return 75;
  return 0;
}

function platformResolutionBasis(platform,q){
  const query=normalize(q), name=normalize(platform);
  if(query===name)return 'platform exact';
  const canonical=canonicalPlatformForTechnologyQuery(q);
  if(canonical&&normalize(canonical)===name)return 'platform alias exact';
  if(name.startsWith(query))return 'platform prefix';
  if(name.includes(query))return 'platform contains';
  return 'platform';
}

function resolutionCandidateKey(candidate){
  if(candidate.kind==='platform')return `platform|${normalize(candidate.platform)}`;
  return `${candidate.view}|${candidate.item?.external_id||''}`;
}

function resolutionCandidateLabel(candidate){
  if(candidate.kind==='platform')return candidate.platform||'ATT&CK Platform';
  return candidate.item?.name||candidate.item?.external_id||'ATT&CK Entity';
}

function investigationCandidates(query=(investigation.query||''),scopeKey=investigation.searchScope){
  const q=(query||'').trim();
  if(!q||!state.data)return [];
  const cfg=INVESTIGATION_SEARCH_SCOPES[scopeKey]||INVESTIGATION_SEARCH_SCOPES.all;
  const rows=[];
  for(const view of cfg.views||[]){
    for(const item of state.data?.[view]||[]){
      const score=directMatchScore(item,q);
      if(score)rows.push({kind:'entity',view,item,score,basis:directMatchBasis(item,q)});
    }
  }
  if(cfg.includePlatforms){
    for(const platform of investigationPlatformValues()){
      const score=platformResolutionScore(platform,q);
      if(score)rows.push({kind:'platform',platform,score,basis:platformResolutionBasis(platform,q)});
    }
  }
  const seen=new Set();
  return rows
    .sort((a,b)=>b.score-a.score || resolutionCandidateLabel(a).localeCompare(resolutionCandidateLabel(b)))
    .filter(row=>{const key=resolutionCandidateKey(row);if(seen.has(key))return false;seen.add(key);return true;})
    .slice(0,20);
}

function resolutionCandidateType(candidate){
  if(candidate.kind==='platform')return 'ATT&CK Platform';
  if(candidate.view==='actors')return 'Threat Actor';
  if(candidate.view==='software')return candidate.item?.software_type==='tool'?'Software · Tool':'Software · Malware/Tool';
  if(candidate.view==='techniques')return 'Technique';
  return VIEW_LABELS[candidate.view]||candidate.view;
}

function resolutionCandidateId(candidate){
  return candidate.kind==='platform'?(candidate.platform||''):candidate.item?.external_id||'';
}

function serializeResolutionCandidate(candidate){
  if(!candidate)return null;
  return candidate.kind==='platform'
    ? {kind:'platform',platform:candidate.platform}
    : {kind:'entity',view:candidate.view,id:candidate.item?.external_id||''};
}

function storedResolutionCandidate(candidates){
  const stored=investigation.resolvedTarget;
  if(!stored)return null;
  return candidates.find(candidate=>{
    if(stored.kind==='platform')return candidate.kind==='platform'&&normalize(candidate.platform)===normalize(stored.platform);
    return candidate.kind==='entity'&&candidate.view===stored.view&&candidate.item?.external_id===stored.id;
  })||null;
}

function safeAutoResolution(candidate){
  if(!candidate)return false;
  const basis=(candidate.basis||'').toLowerCase();
  return basis==='name exact' || basis==='id exact' || basis==='alias exact' || basis==='platform exact' || basis==='platform alias exact';
}

function investigationResolution(query=(investigation.query||'')){
  const candidates=investigationCandidates(query);
  if(!candidates.length)return {candidates,selected:null,mode:'none',top:[]};
  const topScore=candidates[0].score;
  const top=candidates.filter(x=>x.score===topScore);
  const stored=storedResolutionCandidate(candidates);
  if(stored)return {candidates,selected:stored,mode:'selected',top};
  // Auto-resolution is intentionally limited to exact / canonical-exact matches.
  // Prefix and contains matches are suggestions only: users may still be typing
  // (for example, "pan" before "panda"), so never lock the investigation target yet.
  if(top.length===1 && safeAutoResolution(top[0]))return {candidates,selected:top[0],mode:'auto',top};
  return {candidates,selected:null,mode:'ambiguous',top};
}

function candidateEntry(candidate){
  if(!candidate)return investigation.entry||'actors';
  if(candidate.kind==='platform')return 'technology';
  if(candidate.view==='actors')return 'actors';
  if(candidate.view==='software')return 'software';
  if(candidate.view==='techniques')return 'technology';
  return 'actors';
}

function candidateCardHtml(candidate,{active=false,primary=false}={}){
  const key=resolutionCandidateKey(candidate);
  const id=resolutionCandidateId(candidate);
  const aliases=candidate.kind==='entity'?(candidate.item?.aliases||[]):[];
  const meta=candidate.kind==='entity'?matchMeta(candidate.view,candidate.item):'ATT&CK platform metadata';
  return `<button type="button" class="resolution-candidate ${active?'active ':''}${primary?'primary ':''}${candidate.kind==='platform'?'platform':candidate.view}" data-resolution-key="${esc(key)}" data-resolution-kind="${esc(candidate.kind)}" ${candidate.kind==='platform'?`data-resolution-platform="${esc(candidate.platform)}"`:`data-resolution-view="${esc(candidate.view)}" data-resolution-id="${esc(id)}"`}>
    <span class="resolution-candidate-type">${esc(resolutionCandidateType(candidate))}</span>
    <strong>${esc(resolutionCandidateLabel(candidate))}</strong>
    <small>${id&&normalize(id)!==normalize(resolutionCandidateLabel(candidate))?`${esc(id)} · `:''}${esc(meta)}</small>
    <span class="resolution-basis">${esc(candidate.basis||'match')}</span>
    ${aliases.length?`<em>${esc(aliases.slice(0,3).join(' · '))}</em>`:''}
  </button>`;
}

function renderInvestigationResolution(){
  const box=$('investigation-resolution');
  if(!box)return;
  const query=(investigation.query||'').trim();
  if(!query){
    box.innerHTML='<div class="resolution-empty"><b>名前・Alias・ATT&amp;CK IDを入力</b><span>種類が分からない場合はSearch scope: Allのままで検索できます。</span></div>';
    return;
  }
  const resolution=investigationResolution(query);
  if(!resolution.candidates.length){
    box.innerHTML=`<div class="resolution-empty not-found"><b>ATT&amp;CK Entityを特定できませんでした</b><span>別の表記を試すか、Explorerで広く検索してください。</span><button type="button" data-scroll-explorer>Explorerで検索する ↓</button></div>`;
    return;
  }
  const selected=resolution.selected;
  const selectedKey=selected?resolutionCandidateKey(selected):'';
  const topScore=resolution.candidates[0]?.score||0;
  // While the user is still typing a prefix (e.g. pan → panda), do not let the
  // single prefix hit hide useful contains matches. Exact matches stay focused;
  // contains-only searches keep the strongest tier; prefix searches show a
  // broader candidate set so the user can see where the query is heading.
  let best;
  let candidateHeading='BEST MATCHES';
  if(topScore>=130){
    best=resolution.candidates.filter(c=>c.score===topScore).slice(0,8);
  }else if(topScore>=90){
    best=resolution.candidates.filter(c=>c.score>=65).slice(0,8);
    candidateHeading='MATCHING CANDIDATES';
  }else{
    best=resolution.candidates.filter(c=>c.score===topScore).slice(0,8);
  }
  const primaryKeys=new Set(best.map(resolutionCandidateKey));
  const other=resolution.candidates.filter(c=>!primaryKeys.has(resolutionCandidateKey(c)));
  const targetName=selected?resolutionCandidateLabel(selected):'';
  const targetType=selected?resolutionCandidateType(selected):'';
  const status=resolution.mode==='ambiguous'
    ? `<div class="resolution-status ambiguous"><div class="resolution-status-copy"><b>${candidateHeading==='MATCHING CANDIDATES'?'一致候補があります':best.length===1?'最上位候補があります':`${best.length}件の最上位候補があります`}</b><span>${topScore>=90&&topScore<130?'前方一致だけでなく部分一致も表示しています。入力を続けるか、候補を選択してください。':best.length===1?'前方一致・部分一致では自動確定しません。入力を続けるか、この候補を選択してください。':'調査対象を1つ選択してください。曖昧なまま分析は開始しません。'}</span></div></div>`
    : `<div class="resolution-status resolved"><div class="resolution-status-copy"><b>${resolution.mode==='auto'?'自動解決':'選択済み'}: ${esc(targetType)} · ${esc(targetName)}</b><span>${esc(selected.basis||'match')}。ここでは調査対象だけを確定します。実行条件は画面下部のLaunch Barで確認できます。</span></div></div>`;
  const bestSection=`<section class="resolution-group best"><div class="resolution-group-heading"><strong>${candidateHeading}</strong><span>${best.length}件</span></div><div class="resolution-candidate-grid">${best.map(c=>candidateCardHtml(c,{active:resolutionCandidateKey(c)===selectedKey,primary:true})).join('')}</div></section>`;
  const otherSection=other.length
    ? `<details class="resolution-other"><summary><span>OTHER MATCHES</span><b>${other.length}件</b><small>一致度の低い候補を表示</small></summary><div class="resolution-candidate-grid">${other.map(c=>candidateCardHtml(c,{active:resolutionCandidateKey(c)===selectedKey,primary:false})).join('')}</div></details>`
    : '';
  box.innerHTML=`${status}${bestSection}${otherSection}`;
}

function renderInvestigationWorkflow(){
  if(!$('investigation-workflow'))return;
  renderExternalLaunchContext();
  document.querySelectorAll('[data-investigation-search-scope]').forEach(b=>{
    const active=b.dataset.investigationSearchScope===investigation.searchScope;
    b.classList.toggle('active',active);
    b.setAttribute('aria-pressed',active?'true':'false');
  });
  document.querySelectorAll('[data-investigation-lens]').forEach(b=>{
    const active=b.dataset.investigationLens===investigation.lensKey;
    b.classList.toggle('active',active);
    b.setAttribute('aria-pressed',active?'true':'false');
  });
  const q=$('investigation-query'); if(q && document.activeElement!==q) q.value=investigation.query||'';
  renderInvestigationResolution();

  const lens=INVESTIGATION_LENSES[investigation.lensKey]||INVESTIGATION_LENSES.general;
  const lensSummary=$('investigation-lens-summary');
  if(lensSummary)lensSummary.innerHTML=`<div><span class="lens-type ${lens.kind==='attck-native'?'native':lens.kind==='curated'?'curated':'general'}">${lens.kind==='attck-native'?'ATT&CK-NATIVE':lens.kind==='curated'?'DASHBOARD-CURATED':'GENERAL'}</span><strong>${esc(lens.label)}</strong></div><small>${esc(lens.help)}</small>`;
  const currentLens=$('context-current-lens'); if(currentLens)currentLens.textContent=lens.label;
  const currentLensHelp=$('context-current-lens-help'); if(currentLensHelp)currentLensHelp.textContent=lens.help;

  const overlaySelect=$('environment-overlay-select');
  if(overlaySelect && document.activeElement!==overlaySelect) overlaySelect.value=investigation.overlayKey;
  const overlay=environmentOverlay(); const labels=scopeItemLabels(overlay); const overlaySummary=$('environment-overlay-summary');
  const overlayMode=ENVIRONMENT_VIEWS[investigation.overlayKey]?.mode||'none';
  const currentOverlay=$('context-current-overlay'); if(currentOverlay)currentOverlay.textContent=overlayLabel();
  if(overlaySummary){
    if(overlayMode==='none') overlaySummary.innerHTML='<div class="overlay-empty"><b>Environment Overlayは使用しません</b><span>My Environmentが未登録でもInvestigationはそのまま実行できます。</span></div>';
    else overlaySummary.innerHTML=`<div class="scope-summary-head"><div><strong>${esc(overlayLabel())}</strong><span>Environment Profileから ${itemCount(overlay)}件を選択</span></div>${overlayMode==='saved'||overlayMode==='custom'?'<button type="button" class="scope-edit-inline" data-open-scope-editor>Environment Viewを編集</button>':''}</div><div class="scope-summary-chips">${labels.slice(0,6).map(x=>`<span>${esc(x)}</span>`).join('')}${labels.length>6?`<span>+${labels.length-6} more</span>`:''}${!labels.length?'<span>登録項目なし · Overlayは結果に影響しません</span>':''}</div>`;
  }
  renderCustomScopeOptions();

  const launch=$('investigation-launch-summary');
  const query=(investigation.query||'').trim();
  const resolution=investigationResolution(query);
  const target=resolution.selected;
  const targetName=target?resolutionCandidateLabel(target):'';
  const targetType=target?resolutionCandidateType(target):'';
  if(launch) launch.innerHTML=`<span>READY TO INVESTIGATE</span><b>${target?`${esc(targetType)}: ${esc(targetName)}`:query?`Search: ${esc(query)}`:'対象未入力'}</b><small><strong>Lens: ${esc(lensLabel())}</strong> · Environment Overlay: ${esc(overlayLabel())}</small>`;

  const launchBar=$('investigation-launch');
  const workflow=$('investigation-workflow');
  const shouldFloat=Boolean(target&&!investigation.started);
  if(launchBar)launchBar.classList.toggle('is-floating',shouldFloat);
  if(workflow)workflow.classList.toggle('has-floating-launch',shouldFloat);
  updateBackToTop();
  const contextToggle=$('investigation-context-toggle');
  if(contextToggle)contextToggle.hidden=!target;

  const configure=$('investigation-overlay-configure');
  if(configure){
    const editable=overlayMode==='saved'||overlayMode==='custom';
    configure.hidden=!editable;
    configure.textContent=`${overlayLabel()}を編集 ↓`;
  }
  const start=$('investigation-start');
  if(start){
    const ready=Boolean(query&&target);
    start.disabled=!ready;
    if(!query)start.textContent='調査対象を入力してください';
    else if(!resolution.candidates.length)start.textContent='対象を特定できません';
    else if(!target)start.textContent='候補を選択してください';
    else start.textContent=`${targetName} × ${lensLabel()} を調査 →`;
  }
}

function investigationEntryDefaultView(entry=investigation.entry){
  if(entry==='software')return 'software';
  if(entry==='technology')return 'techniques';
  return 'actors';
}

function investigationEntryForView(view){
  if(view==='actors')return 'actors';
  if(view==='software')return 'software';
  if(view==='techniques')return 'technology';
  return null;
}

function strongestMatchesForViews(query,views){
  const allowed=new Set(views||[]);
  const matches=directMatches(query).filter(m=>allowed.has(m.view));
  if(!matches.length)return [];
  const top=matches[0].score;
  return matches.filter(m=>m.score===top);
}

function broadSearchCount(view,query){
  const q=normalize(query); if(!q)return 0;
  return (state.data?.[view]||[]).reduce((n,item)=>n+(searchText(item,view).includes(q)?1:0),0);
}

function chooseTechnologyView(query){
  const strongest=strongestMatchesForViews(query,['techniques','software']);
  if(strongest.length)return strongest[0].view;
  const techniqueCount=broadSearchCount('techniques',query);
  const softwareCount=broadSearchCount('software',query);
  return softwareCount>techniqueCount?'software':'techniques';
}

function persistInvestigation(){
  try{localStorage.setItem(INVESTIGATION_KEY,JSON.stringify(investigation));}catch{}
}

function syncExplorerToInvestigation({scroll=false,openUnique=false,asInvestigation=false}={}){
  const query=(investigation.query||'').trim();
  const resolution=investigationResolution(query);
  const target=resolution.selected;

  if(target?.kind==='platform'){
    state.view='techniques';
    state.search='';
    state.focusId='';
    state.focusOnly=false;
    state.tactic='';
    state.platform=target.platform||'';
  }else if(target?.kind==='entity'){
    state.view=target.view;
    state.search='';
    state.focusId=openUnique?target.item.external_id:'';
    state.focusOnly=false;
    state.tactic='';
    state.platform='';
  }else{
    state.view=investigationEntryDefaultView();
    state.search=query;
    state.focusId='';
    state.focusOnly=false;
    state.tactic='';
    state.platform='';
  }

  if(asInvestigation){
    if(!target)return;
    investigation.entry=candidateEntry(target);
    investigation.resolvedTarget=serializeResolutionCandidate(target);
    investigation.started=true;
    investigation.result=target.kind==='platform'
      ? {view:'technology-platform',id:'',platform:target.platform,query,entry:investigation.entry,lensKey:investigation.lensKey,overlayKey:investigation.overlayKey}
      : {view:target.view,id:target.item.external_id,query,entry:investigation.entry,lensKey:investigation.lensKey,overlayKey:investigation.overlayKey};
  }

  syncControls();
  renderExplorer();
  persistInvestigation();
  renderInvestigationWorkflow();
  renderInvestigationResult();

  if(target?.kind==='entity'&&openUnique){
    focusEntity(target.view,target.item.external_id,{scroll:false});
  }
  if(asInvestigation)$('investigation-result')?.scrollIntoView({behavior:'smooth',block:'start'});
  else if(scroll)$('explorer')?.scrollIntoView({behavior:'smooth',block:'start'});
}

function startInvestigation(){
  const query=($('investigation-query')?.value||'').trim();
  if(!query)return;
  investigation.query=query;
  const resolution=investigationResolution(query);
  if(!resolution.selected){
    investigation.started=false;
    investigation.result=null;
    persistInvestigation();
    renderInvestigationWorkflow();
    renderInvestigationResult();
    return;
  }
  investigation.resolvedTarget=serializeResolutionCandidate(resolution.selected);
  investigation.entry=candidateEntry(resolution.selected);
  persistInvestigation();
  syncExplorerToInvestigation({scroll:false,openUnique:true,asInvestigation:true});
}


function softwareTechnologyMatches(software, sourceEnvironment=environment){
  const entities=[{view:'software',item:software}];
  for(const id of software.techniques||[]){const x=lookups.techniques.get(id);if(x)entities.push({view:'techniques',item:x});}
  const matched=[],unmatched=[];
  for(const techName of sourceEnvironment.technologies||[]){
    const q=normalize(techName);
    const hits=entities.filter(({item})=>[item.external_id,item.name,...(item.aliases||[])].some(v=>normalize(v)===q));
    if(hits.length)matched.push({technology:techName,hits});else unmatched.push(techName);
  }
  return {matched,unmatched};
}

function techniqueTechnologyMatches(technique, sourceEnvironment=environment){
  const matched=[],unmatched=[];
  for(const techName of sourceEnvironment.technologies||[]){
    const q=normalize(techName);
    const hit=[technique.external_id,technique.name,...(technique.aliases||[])].some(v=>normalize(v)===q);
    if(hit)matched.push({technology:techName,hits:[{view:'techniques',item:technique}]});else unmatched.push(techName);
  }
  return {matched,unmatched};
}

function semanticMetricCard(kind,label,count,help){
  const enabled=Number(count)>0;
  return `<button type="button" class="semantic-card ${kind}${enabled?' action':''}" data-result-scroll="${kind}" ${enabled?'':'disabled'} aria-label="${esc(label)} ${count}件${enabled?'。詳細を見る':'。該当なし'}">
    <span>${esc(label)}</span><b>${count}</b><small>${esc(help)}</small>${enabled?'<em>詳細を見る ↓</em>':''}
  </button>`;
}

function compactEnvironmentRelevance(entity,view){
  const overlayMode=ENVIRONMENT_VIEWS[investigation.overlayKey]?.mode||'none';
  if(overlayMode==='none')return `<div class="result-empty-state overlay-not-used"><b>Not used</b><span>Environment Overlayは任意です。My Environmentなしでも、このInvestigation ResultはATT&amp;CK EvidenceとInvestigation Lensだけで成立します。</span></div>`;
  const stats=resultEnvironmentStats(entity,view);
  const {selectedPlatforms,selectedTechnologies,selectedProducts,platformMatches,techMatches,normalizedMatches}=stats;
  const configured=itemCount(environmentOverlay());
  if(!configured)return `<div class="result-empty-state"><b>${esc(overlayLabel())}: 0 items</b><span>Overlayに環境項目がないため、Environment Relevanceは加算しません。Investigation自体は有効です。</span></div>`;
  const direct=[...platformMatches.map(x=>`<span class="result-evidence-chip"><b>Platform exact</b>${esc(x)}</span>`),...techMatches.matched.flatMap(row=>row.hits.slice(0,2).map(hit=>`<button type="button" class="result-evidence-chip action" data-focus-view="${hit.view}" data-focus-id="${esc(hit.item.external_id)}"><b>Technology exact</b>${esc(row.technology)} · ${esc(hit.item.external_id)}</button>`))];
  const normalized=normalizedMatches.map(row=>`<span class="result-evidence-chip normalized"><b>Normalized</b>${esc(row.productLabel)} → ${esc(row.platform)}</span>`);
  const productLabels=selectedProducts.map(x=>`${x.vendor}${x.product?` / ${x.product}`:' / All products'}`);
  const contextHref=view==='actors'?vulnerabilityDashboardUrl(entity):'../vulnerability-intelligence-dashboard/?scope=my&from=threat-investigation';
  return `<div class="result-relevance-summary semantic-relevance">
    <div class="relevance-semantic-grid">
      ${semanticMetricCard('direct','DIRECT ATT&CK MATCH',stats.directCount,'Overlay項目とATT&CK / entity の直接一致')}
      ${semanticMetricCard('normalized','NORMALIZED ENVIRONMENT OVERLAP',stats.normalizedCount,'自環境との名称正規化による接点')}
      ${semanticMetricCard('context','CONTEXT ONLY',selectedProducts.length,'Vulnerability Intelligence連携用')}
    </div>
    <div class="semantic-detail direct-detail" data-result-section="direct"><strong>Direct ATT&amp;CK Match</strong>${direct.length?`<div class="result-direct-evidence">${direct.join('')}</div>`:'<p class="semantic-empty">Exact platform / entity matchは確認できません。</p>'}</div>
    <div class="semantic-detail normalized-detail" data-result-section="normalized"><div class="semantic-detail-heading"><strong>Normalized Environment Overlap</strong><span>Environment Relevance · 閲覧補助</span></div>${normalized.length?`<div class="result-direct-evidence">${normalized.join('')}</div><p class="semantic-note">Environment ProfileのProduct名をATT&amp;CK Platformへ保守的に正規化した結果です。ATT&amp;CK relationshipや攻撃証拠ではありません。</p>`:'<p class="semantic-empty">現在の保守的な正規化ルールではEnvironment Overlapを確認できません。</p>'}</div>
    <div class="semantic-detail context-detail" data-result-section="context"><div class="semantic-detail-heading"><strong>Context Only</strong><span>Vulnerability Intelligence連携用</span></div>${productLabels.length?`<div class="result-product-context"><div>${productLabels.map(x=>`<span>${esc(x)}</span>`).join('')}</div><a class="semantic-context-link" href="${esc(contextHref)}">このEnvironment Overlayの脆弱性を確認 →</a></div>`:'<p class="semantic-empty">Vulnerability Contextとして使うProductはありません。</p>'}<p class="semantic-note">ProductはCVE照合へ渡すContextです。Actor / Software / Techniqueとの直接Evidenceではありません。</p></div>
    ${selectedPlatforms.length===0&&selectedTechnologies.length===0?'<p class="semantic-boundary-note">Platform / TechnologyがOverlayに未登録でも、Product名が明示的にATT&amp;CK Platformへ正規化できる場合はNormalized Environment Overlapとして別表示します。</p>':''}
  </div>`;
}

function resultEnvironmentStats(entity,view){
  const currentOverlay=environmentOverlay();
  const selectedPlatforms=currentOverlay.platforms||[];
  const selectedTechnologies=currentOverlay.technologies||[];
  const selectedProducts=currentOverlay.products||[];
  const relationshipViews=new Set(['actors','campaigns']);
  const observedPlatforms=relationshipViews.has(view)?actorPlatforms(entity):(entity.platforms||[]);
  const platformMatches=selectedPlatforms.filter(p=>observedPlatforms.some(x=>normalize(x)===normalize(p)));
  const techMatches=relationshipViews.has(view)
    ? technologyEntityMatches(entity,currentOverlay)
    : view==='techniques'
      ? techniqueTechnologyMatches(entity,currentOverlay)
      : softwareTechnologyMatches(entity,currentOverlay);
  const normalizedMatches=normalizedEnvironmentOverlaps(entity,view,currentOverlay);
  return {
    selectedPlatforms, selectedTechnologies, selectedProducts,
    observedPlatforms, platformMatches, techMatches, normalizedMatches,
    directCount: platformMatches.length + techMatches.matched.length,
    normalizedCount: normalizedMatches.length
  };
}

function inflectCountLabel(label,count){
  if(Number(count)!==1)return label;
  const singular={
    actors:'actor',Actors:'Actor',
    techniques:'technique',Techniques:'Technique',
    tactics:'tactic',Tactics:'Tactic',
    campaigns:'campaign',Campaigns:'Campaign',
    platforms:'platform',Platforms:'Platform',
    aliases:'alias',Aliases:'Alias'
  };
  return singular[label]||label;
}

function countPhrase(count,singular,plural=null){
  const n=Number(count)||0;
  return `${n} ${n===1?singular:(plural||`${singular}s`)}`;
}

function resultNextActions(entity,view){
  const stats=resultEnvironmentStats(entity,view);
  const actions=[];
  // Keep the same ordering as FINDING. Zero-count branches are intentionally omitted.
  if(view==='actors'){
    if(entity.techniques?.length)actions.push(`<button type="button" class="next-action" data-related-view="techniques" data-related-search="${esc(entity.external_id)}"><span>TECHNIQUES</span><b>${entity.techniques.length}件を見る →</b><small>How the actor is recorded to operate</small></button>`);
    const tacticCount=actorTacticGroups(entity).length;
    if(tacticCount)actions.push(`<button type="button" class="next-action" data-toggle-result-tactics><span>TACTIC COVERAGE</span><b>${tacticCount}件を見る →</b><small>Tactic別にTechniqueを確認</small></button>`);
    if(entity.software?.length)actions.push(`<button type="button" class="next-action" data-related-view="software" data-related-search="${esc(entity.external_id)}"><span>RELATED SOFTWARE</span><b>${entity.software.length}件を見る →</b><small>ATT&amp;CK direct relationships</small></button>`);
    if(entity.campaigns?.length)actions.push(`<button type="button" class="next-action" data-related-view="campaigns" data-related-search="${esc(entity.external_id)}"><span>CAMPAIGNS</span><b>${entity.campaigns.length}件を見る →</b><small>ATT&amp;CK attributed / uses relationships</small></button>`);
  }else if(view==='software'){
    if(entity.actors?.length)actions.push(`<button type="button" class="next-action" data-related-view="actors" data-related-search="${esc(entity.external_id)}"><span>RELATED ACTORS</span><b>${entity.actors.length}件を見る →</b><small>Who ATT&amp;CK links to this software</small></button>`);
    if(entity.techniques?.length)actions.push(`<button type="button" class="next-action" data-related-view="techniques" data-related-search="${esc(entity.external_id)}"><span>TECHNIQUES</span><b>${entity.techniques.length}件を見る →</b><small>Recorded behaviors and techniques</small></button>`);
    if(entity.campaigns?.length)actions.push(`<button type="button" class="next-action" data-related-view="campaigns" data-related-search="${esc(entity.external_id)}"><span>CAMPAIGNS</span><b>${entity.campaigns.length}件を見る →</b><small>Campaign relationships recorded in ATT&amp;CK</small></button>`);
  }else if(view==='techniques'){
    if(entity.actors?.length)actions.push(`<button type="button" class="next-action" data-related-view="actors" data-related-search="${esc(entity.external_id)}"><span>RELATED ACTORS</span><b>${entity.actors.length}件を見る →</b><small>Actors ATT&amp;CK links to this technique</small></button>`);
    if(entity.software?.length)actions.push(`<button type="button" class="next-action" data-related-view="software" data-related-search="${esc(entity.external_id)}"><span>RELATED SOFTWARE</span><b>${entity.software.length}件を見る →</b><small>Software ATT&amp;CK links to this technique</small></button>`);
    if(entity.campaigns?.length)actions.push(`<button type="button" class="next-action" data-related-view="campaigns" data-related-search="${esc(entity.external_id)}"><span>CAMPAIGNS</span><b>${entity.campaigns.length}件を見る →</b><small>Campaign relationships recorded in ATT&amp;CK</small></button>`);
  }
  if(stats.selectedProducts.length){
    const href=view==='actors'?vulnerabilityDashboardUrl(entity):'../vulnerability-intelligence-dashboard/?scope=my&from=threat-investigation';
    actions.push(`<a class="next-action context-action" href="${esc(href)}"><span>VULNERABILITY CONTEXT</span><b>Environment Overlayの脆弱性を見る →</b><small>Product context only — not direct threat evidence</small></a>`);
  }
  return `<div class="next-investigation-grid">${actions.join('')}</div>`;
}

function resultTargetProfile(entity,view){
  const typeLabel={actors:'Threat Actor',software:'Software',techniques:'Technique'}[view]||'ATT&CK Entity';
  return `<div class="finding-target"><div class="finding-target-main"><span>TARGET</span><strong>${esc(typeLabel)} · ${esc(entity.name)}</strong><small>${esc(entity.external_id)}</small><button type="button" data-focus-view="${view}" data-focus-id="${esc(entity.external_id)}" data-focus-only="true">${esc(typeLabel)} Profileを見る →</button></div></div>`;
}

function resultAttributeButton(key,label,values){
  const count=(values||[]).length;
  const shownLabel=inflectCountLabel(label,count);
  if(!count)return `<span><b>0</b> ${esc(shownLabel)}</span>`;
  return `<button type="button" data-toggle-result-attribute="${esc(key)}" aria-expanded="false" aria-label="${count} ${esc(shownLabel)} の内訳を見る"><b>${count}</b> ${esc(shownLabel)}<em>見る →</em></button>`;
}

function resultAttributeBreakdown(key,title,values,{note='',formatter=null}={}){
  const rows=(values||[]).map(v=>formatter?formatter(v):String(v));
  if(!rows.length)return '';
  return `<div class="result-attribute-breakdown" data-result-attribute-panel="${esc(key)}" hidden><div class="result-attribute-breakdown-head"><strong>${esc(title)}</strong>${note?`<span>${esc(note)}</span>`:''}</div><div class="result-attribute-chips">${rows.map(v=>`<span>${esc(v)}</span>`).join('')}</div></div>`;
}

function resultLensSection(entity,view){
  const lens=INVESTIGATION_LENSES[investigation.lensKey]||INVESTIGATION_LENSES.general;
  if(lens.kind==='general'){
    return `<section class="result-context-strip"><span>CONTEXT</span><strong>Lens: General</strong><em>テーマによる絞り込みなし</em></section>`;
  }
  return `<section class="result-block lens-relevance-block result-full result-secondary-block"><p class="detail-kicker">LENS RELEVANCE</p><h4>${esc(lensLabel())}として見る</h4>${lensRelevanceHtml(entity,view)}</section>`;
}

function resultContextSections(entity,view){
  const lens=INVESTIGATION_LENSES[investigation.lensKey]||INVESTIGATION_LENSES.general;
  const overlayMode=ENVIRONMENT_VIEWS[investigation.overlayKey]?.mode||'none';
  if(lens.kind==='general'&&overlayMode==='none'){
    return `<section class="result-context-strip"><span>CONTEXT</span><strong>Lens: General</strong><em>Overlay: Not used</em></section>`;
  }
  let html=resultLensSection(entity,view);
  if(overlayMode==='none'){
    html+=`<section class="result-context-strip subtle"><span>OVERLAY</span><strong>Not used</strong><em>自環境との照合なし</em></section>`;
  }else{
    html+=environmentResultSection(entity,view);
  }
  return html;
}

function resultEvidenceHtml(view){
  const subject={actors:'Threat Actor',software:'Software',techniques:'Technique',campaigns:'Campaign'}[view]||'Entity';
  return `<div class="evidence-boundary-grid evidence-boundary-grid-v067">
    <div><strong>DIRECT ATT&amp;CK EVIDENCE</strong><span>MITRE ATT&amp;CK ${subject} metadata、platform metadata、relationship、Entity名 / Alias / IDのexact match。</span></div>
    <div><strong>INVESTIGATION LENS</strong><span>今回の調査観点。ATT&amp;CK-native LensとDashboard-curated Lensを区別し、My Environmentとは独立して評価します。</span></div>
    <div><strong>ENVIRONMENT OVERLAY · OPTIONAL</strong><span>My Environmentを任意で重ねた追加Context。Normalized overlapやProduct contextをATT&amp;CK direct evidenceと区別します。</span></div>
    <div><strong>NOT INFERRED</strong><span>共通TechniqueやEnvironment overlapだけからActor ↔ CVE / Actor ↔ Productを推定しません。独自の危険度・攻撃確率・リスクスコアも付与しません。</span></div>
  </div>`;
}

function resultFactButton(label,count,relatedView,search,extra=''){
  const enabled=Number(count)>0&&relatedView;
  const shownLabel=inflectCountLabel(label,count);
  if(!enabled)return `<span><b>${count}</b> ${esc(shownLabel)}${extra?`<small>${esc(extra)}</small>`:''}</span>`;
  return `<button type="button" data-related-view="${esc(relatedView)}" data-related-search="${esc(search)}" aria-label="${count} ${esc(shownLabel)} の関連データを見る"><b>${count}</b> ${esc(shownLabel)}${extra?`<small>${esc(extra)}</small>`:''}<em>見る →</em></button>`;
}

function resultActorTacticButton(actor){
  const groups=actorTacticGroups(actor);
  if(!groups.length)return `<span><b>0</b> tactics</span>`;
  return `<button type="button" data-toggle-result-tactics aria-expanded="false" aria-label="${groups.length} ${esc(inflectCountLabel('tactics',groups.length))} の内訳を見る"><b>${groups.length}</b> ${esc(inflectCountLabel('tactics',groups.length))}<em>見る →</em></button>`;
}

function resultActorTacticBreakdown(actor){
  const groups=actorTacticGroups(actor);
  if(!groups.length)return '';
  return `<div class="result-tactic-breakdown" data-result-tactics hidden><div class="result-tactic-breakdown-head"><strong>TACTIC COVERAGE</strong><span>各Tacticを選ぶと、${esc(actor.name)} に紐付くTechniqueだけを表示します。</span></div><div class="result-tactic-chips">${groups.map(g=>`<button type="button" data-related-view="techniques" data-related-search="${esc(actor.external_id)}" data-related-tactic="${esc(g.tactic)}"><span>${esc(tacticLabel(g.tactic))}</span><b>${g.techniques.length}</b></button>`).join('')}</div></div>`;
}

function environmentResultSection(entity,view){
  if((ENVIRONMENT_VIEWS[investigation.overlayKey]?.mode||'none')==='none')return `<section class="result-block environment-overlay-block result-full overlay-not-used-compact"><p class="detail-kicker">ENVIRONMENT OVERLAY · OPTIONAL</p><div class="overlay-not-used-line"><strong>Not used</strong><span>自環境との照合は行っていません</span></div></section>`;
  return `<section class="result-block environment-overlay-block result-full"><p class="detail-kicker">ENVIRONMENT RELEVANCE · OPTIONAL</p><h4>${esc(overlayLabel())}</h4>${compactEnvironmentRelevance(entity,view)}</section>`;
}

function platformEnvironmentResultSection(platform){
  if((ENVIRONMENT_VIEWS[investigation.overlayKey]?.mode||'none')==='none')return `<section class="result-block environment-overlay-block result-full overlay-not-used-compact"><p class="detail-kicker">ENVIRONMENT OVERLAY · OPTIONAL</p><div class="overlay-not-used-line"><strong>Not used</strong><span>自環境との照合は行っていません</span></div></section>`;
  return `<section class="result-block environment-overlay-block result-full"><p class="detail-kicker">ENVIRONMENT RELEVANCE · OPTIONAL</p><h4>${esc(overlayLabel())}</h4>${platformEnvironmentRelevance(platform)}</section>`;
}

function platformResultContextSections(platform){
  const lens=INVESTIGATION_LENSES[investigation.lensKey]||INVESTIGATION_LENSES.general;
  const overlayMode=ENVIRONMENT_VIEWS[investigation.overlayKey]?.mode||'none';
  if(lens.kind==='general'&&overlayMode==='none'){
    return `<section class="result-context-strip"><span>CONTEXT</span><strong>Lens: General</strong><em>Overlay: Not used</em></section>`;
  }
  let html=lens.kind==='general'
    ? `<section class="result-context-strip"><span>CONTEXT</span><strong>Lens: General</strong><em>テーマによる絞り込みなし</em></section>`
    : `<section class="result-block lens-relevance-block result-full result-secondary-block"><p class="detail-kicker">LENS RELEVANCE</p><h4>${esc(lensLabel())}として見る</h4>${platformLensRelevance(platform)}</section>`;
  if(overlayMode==='none'){
    html+=`<section class="result-context-strip subtle"><span>OVERLAY</span><strong>Not used</strong><em>自環境との照合なし</em></section>`;
  }else{
    html+=platformEnvironmentResultSection(platform);
  }
  return html;
}

function actorResultHtml(actor){
  const aliases=uniq((actor.aliases||[]).filter(a=>normalize(a)!==normalize(actor.name)));
  const tacticCount=actorTacticGroups(actor).length;
  const finding=`ATT&amp;CKは ${esc(actor.name)} をGroupとして記録し、${countPhrase(actor.techniques?.length||0,'technique')} / ${countPhrase(tacticCount,'tactic')} / ${actor.software?.length||0} software / ${countPhrase(actor.campaigns?.length||0,'campaign')} に紐付けています。`;
  return `<article class="investigation-result-entity actor-result">
    <div class="result-entity-head"><div><span>THREAT ACTOR</span><h3>${esc(actor.name)}</h3><p>${esc(actor.external_id)} · ATT&amp;CK Group · Lens: ${esc(lensLabel())} · Overlay: ${esc(overlayLabel())}</p></div><span class="result-read-order">Finding → Context → Evidence → Further investigation</span></div>
    <section class="result-finding"><p class="detail-kicker">FINDING</p><h4>今回の調査で分かったこと</h4>${resultTargetProfile(actor,'actors')}<p>${finding}</p><div class="finding-facts">${resultFactButton('techniques',actor.techniques?.length||0,'techniques',actor.external_id)}${resultActorTacticButton(actor)}${resultFactButton('software',actor.software?.length||0,'software',actor.external_id)}${resultFactButton('campaigns',actor.campaigns?.length||0,'campaigns',actor.external_id)}${resultAttributeButton('aliases','aliases',aliases)}</div>${resultActorTacticBreakdown(actor)}${resultAttributeBreakdown('aliases','ALIASES RECORDED BY MITRE ATT&CK',aliases,{note:'同じThreat Actorに記録された別名'})}</section>
    ${resultContextSections(actor,'actors')}
    <details class="result-block result-full evidence-result"><summary><span><b>EVIDENCE</b><strong>この表示の根拠を確認</strong></span><small>ATT&amp;CK / Lens / Environment Overlay の境界</small></summary><div class="evidence-result-body">${resultEvidenceHtml('actors')}</div></details>
    <section class="result-block result-full next-investigation"><p class="detail-kicker">FURTHER INVESTIGATION · OPTIONAL</p><h4>必要なときだけ、さらに詳しく調べる</h4><p class="result-guidance">FINDINGと同じ順序で、現在のActor contextに直接つながる関連Entityだけを深掘りします。Target ProfileはFINDINGから開けます。</p>${resultNextActions(actor,'actors')}</section>
  </article>`;
}

function softwareResultHtml(software){
  const aliases=uniq((software.aliases||[]).filter(a=>normalize(a)!==normalize(software.name)));
  const typeLabel=software.software_type==='malware'?'ATT&CK Malware':'ATT&CK Tool';
  const platforms=(software.platforms||[]);
  const finding=`ATT&amp;CKは ${esc(software.name)} を${esc(typeLabel)}として記録し、${countPhrase(software.actors?.length||0,'actor')} / ${countPhrase(software.techniques?.length||0,'technique')} / ${countPhrase(software.campaigns?.length||0,'campaign')} / ${countPhrase(platforms.length,'platform')} に紐付けています。`;
  const platformText=platforms.length?platforms.slice(0,6).map(esc).join(' / '):'platform未記録';
  return `<article class="investigation-result-entity software-result">
    <div class="result-entity-head"><div><span>SOFTWARE</span><h3>${esc(software.name)}</h3><p>${esc(software.external_id)} · ${esc(typeLabel)} · Lens: ${esc(lensLabel())} · Overlay: ${esc(overlayLabel())}</p></div><span class="result-read-order">Finding → Context → Evidence → Further investigation</span></div>
    <section class="result-finding"><p class="detail-kicker">FINDING</p><h4>今回の調査で分かったこと</h4>${resultTargetProfile(software,'software')}<p>${finding}</p><div class="finding-facts">${resultFactButton('actors',software.actors?.length||0,'actors',software.external_id)}${resultFactButton('techniques',software.techniques?.length||0,'techniques',software.external_id)}${resultFactButton('campaigns',software.campaigns?.length||0,'campaigns',software.external_id)}${resultAttributeButton('platforms','platforms',platforms)}${resultAttributeButton('aliases','aliases',aliases)}</div>${resultAttributeBreakdown('platforms','PLATFORMS RECORDED BY MITRE ATT&CK',platforms,{note:'Software metadataのplatforms'})}${resultAttributeBreakdown('aliases','ALIASES RECORDED BY MITRE ATT&CK',aliases,{note:'同じSoftwareに記録された別名'})}</section>
    ${resultContextSections(software,'software')}
    <details class="result-block result-full evidence-result"><summary><span><b>EVIDENCE</b><strong>この表示の根拠を確認</strong></span><small>ATT&amp;CK / Lens / Environment Overlay の境界</small></summary><div class="evidence-result-body">${resultEvidenceHtml('software')}</div></details>
    <section class="result-block result-full next-investigation"><p class="detail-kicker">FURTHER INVESTIGATION · OPTIONAL</p><h4>必要なときだけ、さらに詳しく調べる</h4><p class="result-guidance">FINDINGと同じ順序で、現在のSoftware contextに直接つながる関連Entityだけを深掘りします。Target ProfileはFINDINGから開けます。</p>${resultNextActions(software,'software')}</section>
  </article>`;
}

function platformMetricButton(label,count,view,platform,help){
  if(!count)return `<span class="platform-result-fact passive"><b>0</b> ${esc(label)}<small>${esc(help)}</small></span>`;
  return `<button type="button" class="platform-result-fact" data-platform-related-view="${esc(view)}" data-platform-related-platform="${esc(platform)}"><b>${count}</b> ${esc(label)}<small>${esc(help)}</small><em>見る →</em></button>`;
}

function platformLensRelevance(platform){
  const lens=INVESTIGATION_LENSES[investigation.lensKey]||INVESTIGATION_LENSES.general;
  if(lens.kind==='general')return `<div class="lens-relevance general-lens"><div class="lens-status-line"><span class="lens-type general">GENERAL</span><strong>テーマによる絞り込みなし</strong></div><p>${esc(platform)} のATT&amp;CK Platform metadataをそのまま調査します。</p></div>`;
  const related=platformInvestigationRelated(platform);
  const platformMatch=(lens.platforms||[]).some(x=>normalize(x)===normalize(platform));
  const matchingTechniques=related.techniques.map(id=>lookups.techniques.get(id)).filter(Boolean).filter(t=>(t.tactics||[]).some(x=>(lens.tactics||[]).includes(x)));
  const typeLabel=lens.kind==='attck-native'?'ATT&CK-NATIVE':'DASHBOARD-CURATED';
  return `<div class="lens-relevance"><div class="lens-status-line"><span class="lens-type ${lens.kind==='attck-native'?'native':'curated'}">${typeLabel}</span><strong>${platformMatch?1:0} platform / ${matchingTechniques.length} technique matches</strong></div><p>${esc(lens.help)}</p>${platformMatch?`<div class="result-direct-evidence"><span class="result-evidence-chip"><b>Platform</b>${esc(platform)}</span></div>`:''}${matchingTechniques.length?`<div class="result-direct-evidence">${matchingTechniques.slice(0,12).map(t=>`<button type="button" class="result-evidence-chip action" data-focus-view="techniques" data-focus-id="${esc(t.external_id)}"><b>${esc(t.external_id)}</b>${esc(t.name)}</button>`).join('')}</div>`:(!platformMatch?'<p class="semantic-empty">現在読み込んでいるATT&amp;CK metadataでは、このLens条件に合う接点を確認できません。</p>':'')}<p class="semantic-note">${lens.kind==='attck-native'?'ATT&CK Platform metadataのexact matchを主条件にしています。':'Lensのグルーピングは本ダッシュボード独自の閲覧補助で、MITRE ATT&CKの正式分類ではありません。'}</p></div>`;
}

function platformEnvironmentRelevance(platform){
  const mode=ENVIRONMENT_VIEWS[investigation.overlayKey]?.mode||'none';
  if(mode==='none')return `<div class="result-empty-state overlay-not-used"><b>Not used</b><span>Environment Overlayは任意です。My EnvironmentなしでもPlatform Investigationは実行できます。</span></div>`;
  const overlay=environmentOverlay();
  if(!itemCount(overlay))return `<div class="result-empty-state"><b>${esc(overlayLabel())}: 0 items</b><span>Overlayに項目がないためEnvironment Relevanceは追加しません。</span></div>`;
  const target=normalize(platform);
  const directPlatforms=(overlay.platforms||[]).filter(p=>normalize(p)===target);
  const normalized=[];
  for(const product of overlay.products||[]){
    for(const candidate of productPlatformCandidates(product)){
      if(normalize(candidate)===target) normalized.push(`${product.vendor}${product.product?` / ${product.product}`:' / All products'} → ${platform}`);
    }
  }
  const context=(overlay.products||[]).map(x=>`${x.vendor}${x.product?` / ${x.product}`:' / All products'}`);
  return `<div class="result-relevance-summary semantic-relevance platform-concept-relevance">
    <div class="relevance-semantic-grid">
      ${semanticMetricCard('direct','DIRECT PLATFORM MATCH',directPlatforms.length,'Environment OverlayのPlatformとの完全一致')}
      ${semanticMetricCard('normalized','NORMALIZED ENVIRONMENT OVERLAP',normalized.length,'Product名 → ATT&CK Platformの閲覧補助')}
      ${semanticMetricCard('context','CONTEXT ONLY',context.length,'Vulnerability Intelligence連携用')}
    </div>
    <div class="semantic-detail direct-detail" data-result-section="direct"><strong>Direct Platform Match</strong>${directPlatforms.length?`<div class="result-direct-evidence">${directPlatforms.map(x=>`<span class="result-evidence-chip"><b>Platform exact</b>${esc(x)}</span>`).join('')}</div>`:'<p class="semantic-empty">今回のEnvironment Overlayには同名Platformが登録されていません。</p>'}</div>
    <div class="semantic-detail normalized-detail" data-result-section="normalized"><div class="semantic-detail-heading"><strong>Normalized Environment Overlap</strong><span>Environment Relevance · 閲覧補助</span></div>${normalized.length?`<div class="result-direct-evidence">${normalized.map(x=>`<span class="result-evidence-chip normalized"><b>Normalized</b>${esc(x)}</span>`).join('')}</div><p class="semantic-note">Environment ProfileのProduct名をATT&amp;CK Platformへ保守的に正規化しています。ATT&amp;CK relationshipではありません。</p>`:'<p class="semantic-empty">現在の保守的な正規化ルールではEnvironment Overlapを確認できません。</p>'}</div>
    <div class="semantic-detail context-detail" data-result-section="context"><div class="semantic-detail-heading"><strong>Context Only</strong><span>Vulnerability Intelligence連携用</span></div>${context.length?`<div class="result-product-context"><div>${context.map(x=>`<span>${esc(x)}</span>`).join('')}</div><a class="semantic-context-link" href="../vulnerability-intelligence-dashboard/?scope=my&from=threat-investigation">このEnvironment Overlayの脆弱性を確認 →</a></div>`:'<p class="semantic-empty">Vulnerability Contextとして使うProductはありません。</p>'}<p class="semantic-note">Productは脆弱性調査へ渡すContextであり、Platformとの直接Evidenceではありません。</p></div>
  </div>`;
}

function technologyPlatformResultHtml(platform,query){
  const related=platformInvestigationRelated(platform);
  const normalizedQuery=normalize(query)===normalize(platform)?'':query;
  const findingIntro=normalizedQuery
    ? `入力した ${esc(query)} は、保守的な名称正規化によりATT&amp;CK Platform <b>${esc(platform)}</b> として調査します。`
    : `${esc(platform)} をATT&amp;CK Platformとして調査します。`;
  return `<article class="investigation-result-entity technology-platform-result">
    <div class="result-entity-head"><div><span>TECHNOLOGY / PLATFORM</span><h3>${esc(query||platform)}</h3><p>ATT&amp;CK Platform: ${esc(platform)} · Lens: ${esc(lensLabel())} · Overlay: ${esc(overlayLabel())}</p></div><span class="result-read-order">Finding → Context → Evidence → Further investigation</span></div>
    <section class="result-finding"><p class="detail-kicker">FINDING</p><h4>今回の調査で分かったこと</h4><p>${findingIntro}</p><div class="platform-profile-note"><span>PLATFORM CONTEXT</span><strong>Platformには独立したATT&amp;CK Profileはありません</strong><p>${esc(platform)} はTechnique / Softwareに付与されるPlatform metadataとして扱われます。そのためProfileへのリンクは表示せず、下のSoftware / Techniques / Actors / Campaignsから関連情報を確認します。</p></div><p>ATT&amp;CKのTechnique / Softwareに記録されたPlatform metadataから、${related.software.length} software / ${related.techniques.length} techniques / ${related.actors.length} actors${related.campaigns.length?` / ${related.campaigns.length} campaigns`:''} を辿れます。Actor件数はATT&amp;CKでActorに紐付くTechnique / SoftwareのPlatform metadataから再構成した閲覧用集計です。</p><div class="finding-facts platform-finding-facts">${platformMetricButton('software',related.software.length,'software',platform,'Platform metadata exact')}${platformMetricButton('techniques',related.techniques.length,'techniques',platform,'Platform metadata exact')}${platformMetricButton('actors',related.actors.length,'actors',platform,'Linked Technique / Softwareから再構成')}${platformMetricButton('campaigns',related.campaigns.length,'campaigns',platform,'Linked Platform contextから再構成')}</div></section>
    ${platformResultContextSections(platform)}
    <details class="result-block result-full evidence-result"><summary><span><b>EVIDENCE</b><strong>この表示の根拠を確認</strong></span><small>ATT&amp;CK Platform metadata / Lens / Environment Overlay の境界</small></summary><div class="evidence-result-body"><div class="evidence-boundary-grid"><div><strong>PLATFORM METADATA</strong><span>ATT&amp;CK Technique / Softwareのplatformsフィールドに ${esc(platform)} が記録されているものを直接抽出します。</span></div><div><strong>INVESTIGATION LENS</strong><span>LensはMy Environmentとは独立した調査観点です。Curated LensはMITREの正式分類ではありません。</span></div><div><strong>ENVIRONMENT OVERLAY · OPTIONAL</strong><span>My Environmentを任意で重ねた追加Contextです。名称正規化はATT&amp;CK relationshipではありません。</span></div><div><strong>NOT INFERRED</strong><span>Platformの共有だけからActor ↔ Product、Actor ↔ CVE、攻撃可能性やリスクを推定しません。</span></div></div></div></details>
    <section class="result-block result-full next-investigation"><p class="detail-kicker">FURTHER INVESTIGATION · OPTIONAL</p><h4>${esc(platform)} をもう一段詳しく調べる</h4><p class="result-guidance">Platform metadataで絞った関連EntityだけをExplorerに表示します。Environment OverlayにProductがある場合だけVulnerability Contextを追加します。</p><div class="next-investigation-grid">${related.software.length?`<button type="button" class="next-action" data-platform-related-view="software" data-platform-related-platform="${esc(platform)}"><span>RELATED SOFTWARE</span><b>${related.software.length}件を見る →</b><small>${esc(platform)} platform exact</small></button>`:''}${related.techniques.length?`<button type="button" class="next-action" data-platform-related-view="techniques" data-platform-related-platform="${esc(platform)}"><span>TECHNIQUES</span><b>${related.techniques.length}件を見る →</b><small>${esc(platform)} platform exact</small></button>`:''}${related.actors.length?`<button type="button" class="next-action" data-platform-related-view="actors" data-platform-related-platform="${esc(platform)}"><span>RELATED ACTORS</span><b>${related.actors.length}件を見る →</b><small>linked metadataから再構成</small></button>`:''}${related.campaigns.length?`<button type="button" class="next-action" data-platform-related-view="campaigns" data-platform-related-platform="${esc(platform)}"><span>CAMPAIGNS</span><b>${related.campaigns.length}件を見る →</b><small>${esc(platform)} context</small></button>`:''}${(environmentOverlay().products||[]).length?`<a class="next-action context-action" href="../vulnerability-intelligence-dashboard/?scope=my&from=threat-investigation"><span>VULNERABILITY CONTEXT</span><b>Environment Overlayの脆弱性を見る →</b><small>Product context only — not threat evidence</small></a>`:''}</div></section>
  </article>`;
}

function techniqueResultHtml(technique){
  const aliases=uniq((technique.aliases||[]).filter(a=>normalize(a)!==normalize(technique.name)));
  const platforms=technique.platforms||[];
  const tactics=technique.tactics||[];
  const finding=`ATT&amp;CKは ${esc(technique.name)} をTechnique ${esc(technique.external_id)} として記録し、${countPhrase(technique.actors?.length||0,'actor')} / ${technique.software?.length||0} software / ${countPhrase(technique.campaigns?.length||0,'campaign')} に紐付けています。`;
  const platformText=platforms.length?platforms.slice(0,6).join(' / '):'platform未記録';
  const tacticText=tactics.length?tactics.map(tacticLabel).join(' / '):'tactic未記録';
  return `<article class="investigation-result-entity technique-result">
    <div class="result-entity-head"><div><span>TECHNOLOGY / TECHNIQUE</span><h3>${esc(technique.name)}</h3><p>${esc(technique.external_id)} · ATT&amp;CK Technique · Lens: ${esc(lensLabel())} · Overlay: ${esc(overlayLabel())}</p></div><span class="result-read-order">Finding → Context → Evidence → Further investigation</span></div>
    <section class="result-finding"><p class="detail-kicker">FINDING</p><h4>今回の調査で分かったこと</h4>${resultTargetProfile(technique,'techniques')}<p>${finding}</p><div class="finding-facts">${resultFactButton('actors',technique.actors?.length||0,'actors',technique.external_id)}${resultFactButton('software',technique.software?.length||0,'software',technique.external_id)}${resultFactButton('campaigns',technique.campaigns?.length||0,'campaigns',technique.external_id)}${resultAttributeButton('platforms','platforms',platforms)}${resultAttributeButton('tactics','tactics',tactics)}${resultAttributeButton('aliases','aliases',aliases)}</div>${resultAttributeBreakdown('platforms','PLATFORMS RECORDED BY MITRE ATT&CK',platforms,{note:'Technique metadataのplatforms'})}${resultAttributeBreakdown('tactics','TACTICS RECORDED BY MITRE ATT&CK',tactics,{note:'Technique metadataのtactics',formatter:tacticLabel})}${resultAttributeBreakdown('aliases','ALIASES RECORDED BY MITRE ATT&CK',aliases,{note:'同じTechniqueに記録された別名'})}</section>
    ${resultContextSections(technique,'techniques')}
    <details class="result-block result-full evidence-result"><summary><span><b>EVIDENCE</b><strong>この表示の根拠を確認</strong></span><small>ATT&amp;CK / Lens / Environment Overlay の境界</small></summary><div class="evidence-result-body">${resultEvidenceHtml('techniques')}</div></details>
    <section class="result-block result-full next-investigation"><p class="detail-kicker">FURTHER INVESTIGATION · OPTIONAL</p><h4>必要なときだけ、さらに詳しく調べる</h4><p class="result-guidance">FINDINGと同じ順序で、現在のTechnique contextに直接つながる関連Entityだけを深掘りします。Target ProfileはFINDINGから開けます。</p>${resultNextActions(technique,'techniques')}</section>
  </article>`;
}

function renderInvestigationResult(){
  const body=$('investigation-result-body'),status=$('investigation-result-status'); if(!body)return;
  if(!investigation.started){
    if(status)status.textContent='WAITING';
    body.innerHTML='<div class="investigation-result-placeholder"><span class="step-number">3</span><div><strong>調査条件を設定してください</strong><p>STEP 1で検索して調査対象を確定し、STEP 2のInvestigation Lensを選んで「調査を開始」を押すと結果を表示します。Environment Overlayは任意です。</p></div></div>';
    return;
  }
  const result=investigation.result||{};
  if(status)status.textContent=(result.id||(result.view==='technology-platform'&&result.platform))?'RESULT':'REVIEW';
  const entity=result.id?lookups[result.view]?.get(result.id):null;
  if(entity&&result.view==='actors'){body.innerHTML=actorResultHtml(entity);return;}
  if(entity&&result.view==='software'){body.innerHTML=softwareResultHtml(entity);return;}
  if(entity&&result.view==='techniques'){body.innerHTML=techniqueResultHtml(entity);return;}
  if(result.view==='technology-platform'&&result.platform){body.innerHTML=technologyPlatformResultHtml(result.platform,result.query||investigation.query);return;}
  const label=investigation.entry==='technology'?'Technology':VIEW_LABELS[result.view]||investigation.entry;
  body.innerHTML=`<div class="investigation-result-placeholder review"><span class="step-number">3</span><div><strong>${esc(result.query||investigation.query||'調査対象')}</strong><p>${esc(label)}をResultとして表示できませんでした。STEP 1で候補を選び直すか、Explorerで広く確認してください。</p><button type="button" data-scroll-explorer>Explorerで候補を見る ↓</button></div></div>`;
}

function investigationSummary(actor, aliases, tacticCount) {
  const platforms = actorPlatforms(actor);
  const techCount = actor.techniques?.length || 0;
  const softCount = actor.software?.length || 0;
  const campCount = actor.campaigns?.length || 0;
  const platformText = platforms.length ? platforms.slice(0,8).join(' · ') : 'None recorded';
  return `<section class="investigation-summary actor-attck-overview">
    <div class="investigation-summary-copy">
      <p class="detail-kicker">ATT&amp;CK OVERVIEW</p>
      <h4>What ATT&amp;CK currently records</h4>
      <p>ATT&amp;CK maps <b>${esc(actor.name)}</b> to <b>${techCount}</b> unique techniques across <b>${tacticCount}</b> tactics, with <b>${softCount}</b> related software and <b>${campCount}</b> campaign${campCount===1?'':'s'} in the current dataset.</p>
      <p class="investigation-caveat">Descriptive ATT&amp;CK coverage only. It does not indicate current activity, attribution confidence, attack likelihood, or risk to your environment.</p>
    </div>
    <div class="investigation-facts actor-overview-facts">
      <div><span>Referenced platforms</span><b>${platforms.length}</b><small>${esc(platformText)}</small></div>
      <div><span>ATT&amp;CK profile modified</span><b class="date-value">${esc(fmtDate(actor.modified))}</b><small>source object date</small></div>
    </div>
    <div class="actor-overview-description">
      <strong>MITRE ATT&amp;CK Description (Original)</strong>
      <p class="entity-description">${esc(actor.description||'Description not available.')}</p>
    </div>
  </section>`;
}

function defensiveLensData(actor) {
  const actorTechs = (actor.techniques || []).map(id=>lookups.techniques.get(id)).filter(Boolean);
  return DEFENSIVE_LENSES.map(lens => {
    const techniques = actorTechs.filter(t => (t.tactics || []).some(tactic => lens.tactics.includes(tactic)));
    techniques.sort((a,b)=>a.external_id.localeCompare(b.external_id));
    return {...lens, techniques};
  }).filter(lens => lens.techniques.length);
}

function defensiveRelevance(actor) {
  const lenses = defensiveLensData(actor);
  if (!lenses.length) return '<div class="empty compact-empty">No ATT&CK tactic relationships available for defensive grouping.</div>';
  return `<div class="defensive-lens-summary"><strong>${lenses.length} of ${DEFENSIVE_LENSES.length} lenses represented</strong><span>該当TechniqueのあるLensのみ表示</span></div><div class="defensive-lens-grid">${lenses.map(lens=>`<article class="defensive-lens-card">
    <div class="defensive-lens-heading"><div><strong>${esc(lens.label)}</strong><small>${esc(lens.hint)}</small></div><b>${lens.techniques.length}</b></div>
    <div class="chips defensive-techniques">${chips(lens.techniques.map(t=>t.external_id),'techniques',5)}</div>
  </article>`).join('')}</div>`;
}

function techniquesByTactic(actor) {
  const groups = actorTacticGroups(actor);
  if (!groups.length) return '<span class="muted">None recorded</span>';
  return `<div class="tactic-detail-controls"><button type="button" class="text-control" data-expand-all-tactics>すべて展開</button><button type="button" class="text-control" data-collapse-all-tactics>すべて閉じる</button></div><div class="tactic-technique-list">${groups.map(g=>`<section class="tactic-technique-row collapsed" data-tactic-row="${esc(g.tactic)}"><button type="button" class="tactic-row-toggle" data-tactic-toggle aria-expanded="false"><span class="tactic-row-caret" aria-hidden="true">▶</span><strong>${esc(tacticLabel(g.tactic))}</strong><span class="tactic-count">${g.techniques.length}</span></button><div class="tactic-row-content" hidden><div class="chips">${chips(g.techniques.map(t=>t.external_id),'techniques',999)}</div></div></section>`).join('')}</div>`;
}

function setTacticRowExpanded(row, expanded) {
  if (!row) return;
  const toggle = row.querySelector('[data-tactic-toggle]');
  const content = row.querySelector('.tactic-row-content');
  row.classList.toggle('collapsed', !expanded);
  if (toggle) {
    toggle.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    const caret = toggle.querySelector('.tactic-row-caret');
    if (caret) caret.textContent = expanded ? '▼' : '▶';
  }
  if (content) content.hidden = !expanded;
}

function setAllTacticRows(card, expanded) {
  if (!card) return;
  card.querySelectorAll('[data-tactic-row]').forEach(row => setTacticRowExpanded(row, expanded));
}

function openTacticFromCoverage(button) {
  const tactic = button?.dataset.openTactic;
  const card = button?.closest('.entity-card');
  if (!tactic || !card) return;
  const row = [...card.querySelectorAll('[data-tactic-row]')].find(x => x.dataset.tacticRow === tactic);
  if (!row) return;
  const grouping = row.closest('details.profile-subdetails');
  if (grouping) grouping.open = true;
  setTacticRowExpanded(row, true);
  window.setTimeout(()=>row.scrollIntoView({behavior:'smooth',block:'center'}),60);
}

function relationshipActions(items) {
  const buttons = items.filter(x=>x.count>0).map(x=>`<button class="relationship-action ${x.view}" data-related-view="${x.view}" data-related-search="${esc(x.search)}" data-reset-context="true"><span>${esc(x.label)}</span><b>${x.count}</b><small>すべて表示 →</small></button>`);
  return buttons.length ? `<div class="relationship-actions">${buttons.join('')}</div>` : '<span class="muted">No related objects recorded.</span>';
}

function profileHeader(item, kind, subtitle, metrics) {
  return `<div class="entity-profile-header ${kind}"><div><p class="detail-kicker">${esc(VIEW_LABELS[kind.toLowerCase()] || kind)} PROFILE</p><h3>${esc(item.name)}</h3><p>${esc(item.external_id)} · ${esc(subtitle)}</p></div><div class="profile-metrics">${metrics.map(m=>`<span><b>${m.value}</b>${esc(inflectCountLabel(m.label,m.value))}</span>`).join('')}</div></div>`;
}

function genericAttckOverview(item, kind, intro, facts=[]) {
  const factHtml=facts.map(f=>`<div><span>${esc(f.label)}</span><b class="${f.date?'date-value':''}">${esc(String(f.value ?? '—'))}</b>${f.note?`<small>${esc(f.note)}</small>`:''}</div>`).join('');
  return `<section class="investigation-summary entity-attck-overview ${esc(kind)}">
    <div class="investigation-summary-copy">
      <p class="detail-kicker">ATT&amp;CK OVERVIEW</p>
      <h4>What ATT&amp;CK currently records</h4>
      <p>${intro}</p>
      <p class="investigation-caveat">Descriptive ATT&amp;CK coverage only. It does not indicate current activity, attribution confidence, attack likelihood, or risk to your environment.</p>
    </div>
    <div class="investigation-facts entity-overview-facts">${factHtml}</div>
    <div class="actor-overview-description">
      <strong>MITRE ATT&amp;CK Description (Original)</strong>
      <p class="entity-description">${esc(item.description||'Description not available.')}</p>
    </div>
  </section>`;
}

function profileIaSection(number, label, count, lead, body, extra='') {
  return `<section class="detail-section profile-ia-section" data-profile-section="${esc(label.toLowerCase().replace(/\s+/g,'-'))}">
    <div class="profile-ia-heading"><div><span>${String(number).padStart(2,'0')}</span><strong>${esc(label)}</strong></div><b>${esc(String(count))}</b></div>
    ${lead?`<p class="section-lead">${lead}</p>`:''}
    ${body}
    ${extra}
  </section>`;
}

function actorCard(a) {
  const aliases = actorAliases(a);
  const aliasSummary = aliases.slice(0,4).join(' · ');
  const aliasMore = aliases.length > 4 ? ` · +${aliases.length-4}` : '';
  const tacticCount = actorTacticGroups(a).length;
  const open = state.focusId === a.external_id ? ' open' : '';
  const techCount = a.techniques?.length || 0;
  const softCount = a.software?.length || 0;
  const campCount = a.campaigns?.length || 0;
  return `<article class="entity-card actors${open}" data-entity-id="${esc(a.external_id)}">
    <div class="entity-summary"><div class="entity-id">${esc(a.external_id)}</div><div class="entity-name"><b>${esc(a.name)}</b><small>${esc(aliasSummary || 'No aliases')}${esc(aliasMore)}</small>${relationContextHtml(a,'actors')}</div><div class="entity-stats"><span class="stat">Tech ${techCount}</span><span class="stat">Tactics ${tacticCount}</span><span class="stat">Soft ${softCount}</span><span class="stat">Camp ${campCount}</span></div><div class="entity-meta">Modified<small>${fmtDate(a.modified)}</small></div></div>
    <div class="entity-details actor-profile">
      ${profileHeader(a,'actors','ATT&CK Group',[{label:'Techniques',value:techCount},{label:'Tactics',value:tacticCount},{label:'Software',value:softCount},{label:'Campaigns',value:campCount},{label:'Aliases',value:aliases.length}])}
      ${investigationRelevance(a)}
      ${investigationSummary(a,aliases,tacticCount)}

      <section class="detail-section profile-ia-section techniques-section" data-profile-section="techniques">
        <div class="profile-ia-heading"><div><span>01</span><strong>Techniques</strong></div><b>${techCount}</b></div>
        <p class="section-lead">ATT&amp;CKで${esc(a.name)}に直接紐付くTechniqueです。必要に応じてTactic別に展開できます。</p>
        <div class="chips">${chips(a.techniques,'techniques',24)}</div>
        <details class="profile-subdetails technique-grouping">
          <summary>Group Techniques by Tactic</summary>
          <div class="profile-subdetails-body">${techniquesByTactic(a)}</div>
        </details>
      </section>

      <section class="detail-section profile-ia-section tactics-section" data-profile-section="tactics">
        <div class="profile-ia-heading"><div><span>02</span><strong>Tactics</strong></div><b>${tacticCount}</b></div>
        <p class="section-lead">Techniqueに記録されたATT&amp;CK Tacticを集計しています。各Tacticを選ぶと、上のTechniquesを該当Tacticへ展開します。</p>
        ${actorTacticCoverage(a)}
        <p class="micro-note"><b>集計上の注意:</b> 1つのTechniqueが複数Tacticに属する場合があるため、Tactic別件数の合計はUnique Techniquesと一致しない場合があります。</p>
      </section>

      <section class="detail-section profile-ia-section software-section" data-profile-section="software">
        <div class="profile-ia-heading"><div><span>03</span><strong>Software</strong></div><b>${softCount}</b></div>
        <p class="section-lead">ATT&amp;CKで${esc(a.name)}に直接Relationshipで紐付くSoftwareです。</p>
        <div class="chips">${chips(a.software,'software',24)}</div>
      </section>

      <section class="detail-section profile-ia-section campaigns-section" data-profile-section="campaigns">
        <div class="profile-ia-heading"><div><span>04</span><strong>Campaigns</strong></div><b>${campCount}</b></div>
        <p class="section-lead">ATT&amp;CKで${esc(a.name)}に直接Relationshipで紐付くCampaignです。</p>
        <div class="chips">${chips(a.campaigns,'campaigns',24)}</div>
        ${campCount===0?'<p class="micro-note">No direct ATT&amp;CK campaign relationship is recorded for this Threat Actor in the loaded dataset.</p>':''}
      </section>

      <section class="detail-section profile-ia-section aliases-section" data-profile-section="aliases">
        <div class="profile-ia-heading"><div><span>05</span><strong>Aliases</strong></div><b>${aliases.length}</b></div>
        <p class="section-lead">同じATT&amp;CK Groupに記録された別名です。Actor名とAliasの両方が検索対象です。</p>
        <div class="chips">${aliasChips(aliases)}</div>
      </section>

      <section class="detail-section dashboard-analysis-section defensive-relevance-section">
        <div class="dashboard-analysis-heading"><div><p class="detail-kicker">DASHBOARD ANALYSIS</p><strong>Defensive Investigation Lenses</strong></div><span>dashboard-derived · no risk score</span></div>
        <p class="section-lead">ATT&amp;CK Tacticsを6つの防御側調査Lensに再構成し、関連Techniqueを見つけやすくする本ダッシュボード独自の閲覧補助です。該当TechniqueのあるLensだけを表示します。</p>
        ${defensiveRelevance(a)}
        <p class="micro-note"><b>独自表示:</b> MITRE ATT&amp;CKの正式なTactic分類、対策優先度、Control mapping、リスクスコアではありません。Techniqueが複数Tacticに属する場合、複数のLensに現れるため、Lens別件数の合計はUnique Techniquesと一致しない場合があります。</p>
      </section>

      ${a.url?`<a class="source-button" href="${esc(a.url)}" target="_blank" rel="noopener noreferrer">MITRE ATT&amp;CK source ↗</a>`:''}
    </div></article>`;
}

function techniqueCard(t) {
  const open = state.focusId === t.external_id ? ' open' : '';
  const aliases = uniq((t.aliases||[]).filter(a=>normalize(a)!==normalize(t.name)));
  const actorCount=t.actors?.length||0;
  const softwareCount=t.software?.length||0;
  const campaignCount=t.campaigns?.length||0;
  const platformCount=t.platforms?.length||0;
  const tacticCount=t.tactics?.length||0;
  const typeLabel=t.is_subtechnique?'ATT&CK Sub-technique':'ATT&CK Technique';
  const overviewIntro=`ATT&amp;CK records <b>${esc(t.name)}</b> as ${esc(typeLabel)}, with <b>${actorCount}</b> actor relationships, <b>${softwareCount}</b> related software, <b>${campaignCount}</b> campaigns, <b>${platformCount}</b> platform${platformCount===1?'':'s'}, and <b>${tacticCount}</b> tactic${tacticCount===1?'':'s'} in the current dataset.`;
  const tacticButtons=(t.tactics||[]).map(x=>`<button class="chip" data-related-view="techniques" data-related-search="${esc(t.external_id)}" data-related-tactic="${esc(x)}">${esc(tacticLabel(x))}</button>`).join('')||'<span class="muted">None recorded</span>';
  return `<article class="entity-card techniques${open}" data-entity-id="${esc(t.external_id)}">
    <div class="entity-summary"><div class="entity-id">${esc(t.external_id)}</div><div class="entity-name"><b>${esc(t.name)}</b><small>${esc((t.tactics||[]).map(tacticLabel).join(' · ') || 'No tactic')}</small>${relationContextHtml(t,'techniques')}</div><div class="entity-stats"><span class="stat">Actors ${actorCount}</span><span class="stat">Soft ${softwareCount}</span><span class="stat">Camp ${campaignCount}</span><span class="stat">Plat ${platformCount}</span></div><div class="entity-meta">Modified<small>${fmtDate(t.modified)}</small></div></div>
    <div class="entity-details entity-profile">
      ${profileHeader(t,'techniques',typeLabel,[{label:'Actors',value:actorCount},{label:'Software',value:softwareCount},{label:'Campaigns',value:campaignCount},{label:'Platforms',value:platformCount},{label:'Tactics',value:tacticCount},{label:'Aliases',value:aliases.length}])}
      ${investigationRelevance(t)}
      ${genericAttckOverview(t,'techniques',overviewIntro,[{label:'Technique type',value:t.is_subtechnique?'Sub-technique':'Technique',note:t.external_id},{label:'ATT&CK profile modified',value:fmtDate(t.modified),note:'source object date',date:true}])}

      ${profileIaSection(1,'Actors',actorCount,`ATT&amp;CKで${esc(t.name)}に直接Relationshipで紐付くThreat Actorです。`,`<div class="chips">${chips(t.actors,'actors',24)}</div>`)}
      ${profileIaSection(2,'Software',softwareCount,`ATT&amp;CKで${esc(t.name)}に直接Relationshipで紐付くSoftwareです。`,`<div class="chips">${chips(t.software,'software',24)}</div>`)}
      ${profileIaSection(3,'Campaigns',campaignCount,`ATT&amp;CKで${esc(t.name)}に直接Relationshipで紐付くCampaignです。`,`<div class="chips">${chips(t.campaigns,'campaigns',24)}</div>`,campaignCount===0?'<p class="micro-note">No direct ATT&amp;CK campaign relationship is recorded for this Technique in the loaded dataset.</p>':'')}
      ${profileIaSection(4,'Platforms',platformCount,'Technique metadataに記録されたATT&amp;CK Platformです。',`<div class="chips">${(t.platforms||[]).map(x=>`<span class="chip passive">${esc(x)}</span>`).join('')||'<span class="muted">None recorded</span>'}</div>`)}
      ${profileIaSection(5,'Tactics',tacticCount,'Technique metadataに記録されたATT&amp;CK Tacticです。 選択するとExplorerで同じTechnique contextをTacticで絞ります。',`<div class="chips">${tacticButtons}</div>`)}
      ${profileIaSection(6,'Aliases',aliases.length,'同じATT&amp;CK Techniqueに記録された別名です。',`<div class="chips">${aliasChips(aliases)}</div>`)}

      ${t.url?`<a class="source-button" href="${esc(t.url)}" target="_blank" rel="noopener noreferrer">MITRE ATT&amp;CK source ↗</a>`:''}
    </div></article>`;
}

function softwareCard(s) {
  const open = state.focusId === s.external_id ? ' open' : '';
  const aliases = uniq((s.aliases||[]).filter(a=>normalize(a)!==normalize(s.name)));
  const actorCount=s.actors?.length||0;
  const techniqueCount=s.techniques?.length||0;
  const campaignCount=s.campaigns?.length||0;
  const platformCount=s.platforms?.length||0;
  const typeLabel=s.software_type==='malware'?'ATT&CK Malware':'ATT&CK Tool';
  const overviewIntro=`ATT&amp;CK records <b>${esc(s.name)}</b> as ${esc(typeLabel)}, with <b>${actorCount}</b> actor relationships, <b>${techniqueCount}</b> techniques, <b>${campaignCount}</b> campaigns, and <b>${platformCount}</b> platform${platformCount===1?'':'s'} in the current dataset.`;
  return `<article class="entity-card software${open}" data-entity-id="${esc(s.external_id)}">
    <div class="entity-summary"><div class="entity-id">${esc(s.external_id)}</div><div class="entity-name"><b>${esc(s.name)}</b><small>${esc(s.software_type||'software')} · ${esc(aliases.slice(0,4).join(' · ')||'No aliases')}</small>${relationContextHtml(s,'software')}</div><div class="entity-stats"><span class="stat">Actors ${actorCount}</span><span class="stat">Tech ${techniqueCount}</span><span class="stat">Camp ${campaignCount}</span><span class="stat">Plat ${platformCount}</span></div><div class="entity-meta">Modified<small>${fmtDate(s.modified)}</small></div></div>
    <div class="entity-details entity-profile">
      ${profileHeader(s,'software',typeLabel,[{label:'Actors',value:actorCount},{label:'Techniques',value:techniqueCount},{label:'Campaigns',value:campaignCount},{label:'Platforms',value:platformCount},{label:'Aliases',value:aliases.length}])}
      ${investigationRelevance(s)}
      ${genericAttckOverview(s,'software',overviewIntro,[{label:'Software type',value:s.software_type||'software',note:typeLabel},{label:'ATT&CK profile modified',value:fmtDate(s.modified),note:'source object date',date:true}])}

      ${profileIaSection(1,'Actors',actorCount,`ATT&amp;CKで${esc(s.name)}に直接Relationshipで紐付くThreat Actorです。`,`<div class="chips">${chips(s.actors,'actors',24)}</div>`)}
      ${profileIaSection(2,'Techniques',techniqueCount,`ATT&amp;CKで${esc(s.name)}に直接Relationshipで紐付くTechniqueです。`,`<div class="chips">${chips(s.techniques,'techniques',28)}</div>`)}
      ${profileIaSection(3,'Campaigns',campaignCount,`ATT&amp;CKで${esc(s.name)}に直接Relationshipで紐付くCampaignです。`,`<div class="chips">${chips(s.campaigns,'campaigns',24)}</div>`,campaignCount===0?'<p class="micro-note">No direct ATT&amp;CK campaign relationship is recorded for this Software in the loaded dataset.</p>':'')}
      ${profileIaSection(4,'Platforms',platformCount,'Software metadataに記録されたATT&amp;CK Platformです。',`<div class="chips">${(s.platforms||[]).map(x=>`<span class="chip passive">${esc(x)}</span>`).join('')||'<span class="muted">None recorded</span>'}</div>`)}
      ${profileIaSection(5,'Aliases',aliases.length,'同じATT&amp;CK Softwareに記録された別名です。',`<div class="chips">${aliasChips(aliases)}</div>`)}

      ${s.url?`<a class="source-button" href="${esc(s.url)}" target="_blank" rel="noopener noreferrer">MITRE ATT&amp;CK source ↗</a>`:''}
    </div></article>`;
}

function campaignCard(c) {
  const open = state.focusId === c.external_id ? ' open' : '';
  const aliases = uniq((c.aliases||[]).filter(a=>normalize(a)!==normalize(c.name)));
  const actorCount=c.actors?.length||0;
  const techniqueCount=c.techniques?.length||0;
  const softwareCount=c.software?.length||0;
  const hasPeriod=Boolean(c.first_seen||c.last_seen);
  const overviewIntro=`ATT&amp;CK records <b>${esc(c.name)}</b> as a Campaign, with <b>${actorCount}</b> attributed actor relationship${actorCount===1?'':'s'}, <b>${techniqueCount}</b> techniques, and <b>${softwareCount}</b> related software object${softwareCount===1?'':'s'} in the current dataset.`;
  return `<article class="entity-card campaigns${open}" data-entity-id="${esc(c.external_id)}">
    <div class="entity-summary"><div class="entity-id">${esc(c.external_id)}</div><div class="entity-name"><b>${esc(c.name)}</b><small>${esc(aliases.slice(0,4).join(' · ')||'No aliases')}</small>${relationContextHtml(c,'campaigns')}</div><div class="entity-stats"><span class="stat">Actors ${actorCount}</span><span class="stat">Tech ${techniqueCount}</span><span class="stat">Soft ${softwareCount}</span><span class="stat">Period ${hasPeriod?'✓':'—'}</span></div><div class="entity-meta">Modified<small>${fmtDate(c.modified)}</small></div></div>
    <div class="entity-details entity-profile">
      ${profileHeader(c,'campaigns','ATT&CK Campaign',[{label:'Actors',value:actorCount},{label:'Techniques',value:techniqueCount},{label:'Software',value:softwareCount},{label:'Period',value:hasPeriod?'✓':'—'},{label:'Aliases',value:aliases.length}])}
      ${investigationRelevance(c)}
      ${genericAttckOverview(c,'campaigns',overviewIntro,[{label:'Observed period',value:hasPeriod?'Recorded':'Not recorded',note:hasPeriod?`${fmtDate(c.first_seen)} → ${fmtDate(c.last_seen)}`:'No first/last seen dates'},{label:'ATT&CK profile modified',value:fmtDate(c.modified),note:'source object date',date:true}])}

      ${profileIaSection(1,'Actors',actorCount,`ATT&amp;CKで${esc(c.name)}に直接Relationshipで紐付くThreat Actorです。`,`<div class="chips">${chips(c.actors,'actors',24)}</div>`)}
      ${profileIaSection(2,'Techniques',techniqueCount,`ATT&amp;CKで${esc(c.name)}に直接Relationshipで紐付くTechniqueです。`,`<div class="chips">${chips(c.techniques,'techniques',28)}</div>`)}
      ${profileIaSection(3,'Software',softwareCount,`ATT&amp;CKで${esc(c.name)}に直接Relationshipで紐付くSoftwareです。`,`<div class="chips">${chips(c.software,'software',24)}</div>`)}
      ${profileIaSection(4,'Observed Period',hasPeriod?'✓':'—','Campaign metadataに記録された観測期間です。',`<div class="period-row"><span><b>First seen</b>${fmtDate(c.first_seen)}</span><span><b>Last seen</b>${fmtDate(c.last_seen)}</span></div>`)}
      ${profileIaSection(5,'Aliases',aliases.length,'同じATT&amp;CK Campaignに記録された別名です。',`<div class="chips">${aliasChips(aliases)}</div>`)}

      ${c.url?`<a class="source-button" href="${esc(c.url)}" target="_blank" rel="noopener noreferrer">MITRE ATT&amp;CK source ↗</a>`:''}
    </div></article>`;
}

function emptyResultHtml() {
  const q = state.search.trim();
  const anchors = q ? primaryDirectMatches(q) : [];
  if (!q || !anchors.length) return '<div class="empty">該当するデータがありません。</div>';

  const targetLabel = VIEW_TITLES[state.view];
  if (anchors.length === 1) {
    const anchor = anchors[0];
    const anchorLabel = `${anchor.item.external_id} ${anchor.item.name}`;
    const sameView = anchor.view === state.view;
    if (sameView) {
      return `<div class="empty contextual-empty"><strong>ATT&amp;CK上で${esc(anchorLabel)}に直接Relationshipで結ばれた追加の${esc(targetLabel)}はありません。</strong><span>Primary Matchは上のDirect Matchにのみ表示し、この一覧には重複表示していません。</span><small>共通Techniqueなどから推定するDerived / analytical relationshipは表示していません。</small></div>`;
    }
    const specific = state.view === 'campaigns'
      ? '実世界の攻撃活動やベンダー報告上のCampaignが存在しないことを意味するものではありません。'
      : 'ATT&CKに収録されていない関連Entityが実世界に存在しないことを意味するものではありません。';
    return `<div class="empty contextual-empty"><strong>ATT&amp;CK上で${esc(anchorLabel)}に直接関連付けられた${esc(targetLabel)}はありません。</strong><span>${esc(specific)}</span><small>この表示は、現在読み込まれているMITRE ATT&amp;CKデータの直接関係に基づきます。</small></div>`;
  }

  return `<div class="empty contextual-empty"><strong>選択中の${esc(targetLabel)}に直接関連する結果はありません。</strong><span>複数のPrimary Match候補があるため、個別Entityを開いて関係を確認してください。</span><small>ATT&amp;CKに未収録の関係が存在しないことを意味するものではありません。</small></div>`;
}

function renderExplorer() {
  $('explorer-title').textContent = VIEW_TITLES[state.view];
  document.querySelectorAll('#view-switch [data-view]').forEach(b => b.classList.toggle('active',b.dataset.view===state.view));
  renderActiveContext();
  renderSearchInsight();
  let items = filteredItems();
  // A focused entity must remain renderable even when the view contains more
  // than the 500-card display cap. Full Profile drill-down can additionally
  // request focusOnly so the Explorer shows only the investigation subject
  // instead of the entire Software/Actor catalog.
  if (state.focusId) {
    const focused = lookups[state.view]?.get(state.focusId);
    if (focused && matchesContext(focused,state.view)) {
      items = state.focusOnly ? [focused] : [focused, ...items.filter(item => item.external_id !== state.focusId)];
    }
  }
  const anchors = state.search.trim() ? primaryDirectMatches(state.search.trim()) : [];
  $('result-count').textContent = state.focusOnly ? `${items.length.toLocaleString()}件 · focused` : (anchors.length ? `関連 ${items.length.toLocaleString()}件` : `${items.length.toLocaleString()}件`);
  const renderer = {actors:actorCard,techniques:techniqueCard,software:softwareCard,campaigns:campaignCard}[state.view];
  const heading = relatedListHeading();
  $('entity-list').innerHTML = heading + (items.length ? items.slice(0,500).map(renderer).join('') + (items.length>500?'<div class="empty">表示負荷を抑えるため先頭500件を表示しています。検索・フィルターで絞り込んでください。</div>':'') : emptyResultHtml());
}

function jump(view, search='', options={}) {
  state.view = view;
  state.search = search;
  state.focusId = options.focusId || '';
  state.focusOnly = false;
  if (options.resetContext) { state.tactic=''; state.platform=''; }
  if (Object.prototype.hasOwnProperty.call(options,'tactic')) state.tactic = options.tactic || '';
  if (Object.prototype.hasOwnProperty.call(options,'platform')) state.platform = options.platform || '';
  syncControls();
  renderExplorer();
  $('explorer').scrollIntoView({behavior:'smooth',block:'start'});
}

function focusEntity(view,id,options={}) {
  // Explorer is a Further Investigation layer. Opening a profile must not rewrite STEP 1.
  // Direct matches live only in the Entity-aware Search panel. If we keep the
  // ID as the search query, the selected entity is intentionally omitted from
  // the lower relationship list, so there is no profile card to expand.
  // Opening an entity therefore leaves search mode and focuses the canonical
  // card in the selected view.
  state.view = view;
  state.search = '';
  state.focusId = id;
  state.focusOnly = options.only === true;
  state.tactic = '';
  state.platform = '';
  syncControls();
  renderExplorer();
  window.setTimeout(()=>{
    const card = document.querySelector(`[data-entity-id="${CSS.escape(id)}"]`);
    if (card && options.scroll!==false) card.scrollIntoView({behavior:'smooth',block:'start'});
    renderInvestigationWorkflow();
    renderInvestigationResult();
  },100);
}

function clearContext() {
  state.search=''; state.tactic=''; state.platform=''; state.focusId=''; state.focusOnly=false;
  investigation.started=false; investigation.result=null; persistInvestigation();
  syncControls(); renderExplorer(); renderInvestigationWorkflow(); renderInvestigationResult();
}

function updateBackToTop(){
  const btn=$('back-to-top');
  if(!btn)return;
  const visible=window.scrollY>640;
  const launchFloating=$('investigation-launch')?.classList.contains('is-floating');
  btn.classList.toggle('is-visible',visible);
  btn.classList.toggle('with-launch',Boolean(launchFloating));
  btn.setAttribute('aria-hidden',visible?'false':'true');
}

function bindEvents() {
  document.addEventListener('click', (e) => {
    const scrollInvestigation=e.target.closest('[data-scroll-investigation]');
    if(scrollInvestigation){$('investigation-workflow')?.scrollIntoView({behavior:'smooth',block:'start'});return;}
    const scrollExplorer=e.target.closest('[data-scroll-explorer]');
    if(scrollExplorer){
      const focused=currentFocusedEntity();
      if(focused){document.querySelector(`[data-entity-id="${CSS.escape(focused.item.external_id)}"]`)?.scrollIntoView({behavior:'smooth',block:'start'});}
      else syncExplorerToInvestigation({scroll:true,openUnique:false});
      return;
    }
    const searchScopeBtn=e.target.closest('[data-investigation-search-scope]');
    if(searchScopeBtn){
      investigation.searchScope=searchScopeBtn.dataset.investigationSearchScope||'all';
      if(!INVESTIGATION_SEARCH_SCOPES[investigation.searchScope])investigation.searchScope='all';
      investigation.resolvedTarget=null;
      investigation.started=false; investigation.result=null; state.focusOnly=false;
      persistInvestigation();
      renderInvestigationWorkflow(); renderInvestigationResult();
      return;
    }
    const resolutionBtn=e.target.closest('[data-resolution-key]');
    if(resolutionBtn){
      const kind=resolutionBtn.dataset.resolutionKind||'entity';
      const candidates=investigationCandidates();
      const selected=candidates.find(candidate=>{
        if(kind==='platform')return candidate.kind==='platform'&&normalize(candidate.platform)===normalize(resolutionBtn.dataset.resolutionPlatform||'');
        return candidate.kind==='entity'&&candidate.view===(resolutionBtn.dataset.resolutionView||'')&&candidate.item?.external_id===(resolutionBtn.dataset.resolutionId||'');
      });
      if(selected){
        investigation.resolvedTarget=serializeResolutionCandidate(selected);
        investigation.entry=candidateEntry(selected);
        investigation.started=false; investigation.result=null; state.focusOnly=false;
        persistInvestigation();
        renderInvestigationWorkflow(); renderInvestigationResult();
      }
      return;
    }
    const lensBtn=e.target.closest('[data-investigation-lens]');
    if(lensBtn){
      investigation.lensKey=lensBtn.dataset.investigationLens||'general';
      investigation.started=false; investigation.result=null; state.focusOnly=false;
      saveInvestigation();
      return;
    }
    const openScopeEditor=e.target.closest('[data-open-scope-editor], #investigation-overlay-configure');
    if(openScopeEditor){
      const editor=$('investigation-custom-editor');
      if(editor){editor.open=true;setTimeout(()=>editor.scrollIntoView({behavior:'smooth',block:'nearest'}),0);}
      return;
    }
    const closeScopeEditor=e.target.closest('[data-close-scope-editor]');
    if(closeScopeEditor){
      const editor=$('investigation-custom-editor'); if(editor)editor.open=false;
      setTimeout(()=>$('investigation-launch')?.scrollIntoView({behavior:'smooth',block:'nearest'}),0);
      return;
    }
    const applyTemplate=e.target.closest('[data-apply-scope-template]');
    if(applyTemplate){
      const key=applyTemplate.dataset.applyScopeTemplate||'';
      const editor=$('investigation-custom-editor'); if(editor)editor.open=false;
      replaceScopeSelection(key,templateCandidateScope(key));
      setTimeout(()=>$('investigation-launch')?.scrollIntoView({behavior:'smooth',block:'nearest'}),0);
      return;
    }
    const clearScope=e.target.closest('[data-clear-scope]');
    if(clearScope){replaceScopeSelection(clearScope.dataset.clearScope||investigation.overlayKey,emptyScopeItems());return;}
    const quickBtn=e.target.closest('[data-investigation-quick]');
    if(quickBtn){
      const [scope,query]=String(quickBtn.dataset.investigationQuick||'').split('|');
      investigation.searchScope=INVESTIGATION_SEARCH_SCOPES[scope]?scope:'all';
      investigation.query=query||'';
      investigation.resolvedTarget=null;
      investigation.started=false; state.focusOnly=false;
      investigation.result=null;
      if($('investigation-query'))$('investigation-query').value=investigation.query;
      persistInvestigation();
      renderInvestigationWorkflow(); renderInvestigationResult();
      return;
    }
    const contextToggle=e.target.closest('#investigation-context-toggle');
    if(contextToggle){
      const details=$('investigation-context-disclosure');
      if(details){details.open=true;setTimeout(()=>details.scrollIntoView({behavior:'smooth',block:'nearest'}),0);}
      return;
    }
    const startBtn=e.target.closest('#investigation-start');
    if(startBtn){startInvestigation();return;}
    const scrollEnv=e.target.closest('[data-scroll-environment]');
    if(scrollEnv){const disclosure=$('environment-settings-disclosure');const manager=$('environment-profile-manager');const editor=$('environment-editor');if(disclosure)disclosure.open=true;if(manager)manager.open=true;if(editor)editor.open=true;$('my-environment')?.scrollIntoView({behavior:'smooth',block:'start'});return;}

    const envSuggestion=e.target.closest('[data-apply-environment-product-suggestion]');
    if(envSuggestion){
      $('environment-vendor-input').value=envSuggestion.dataset.vendor||'';
      $('environment-product-input').value=envSuggestion.dataset.product||'';
      populateEnvironmentProductSuggestions(); renderEnvironmentProductSuggestion();
      return;
    }

    const envProductAdd=e.target.closest('#environment-product-add');
    if(envProductAdd){addEnvironmentProduct();return;}

    const envTechnologyAdd=e.target.closest('#environment-technology-add');
    if(envTechnologyAdd){addEnvironmentTechnology();return;}

    const envFixProduct=e.target.closest('[data-fix-environment-product]');
    if(envFixProduct){
      const rows=[...(environment.products||[])], idx=Number(envFixProduct.dataset.fixEnvironmentProduct);
      if(Number.isInteger(idx)&&rows[idx]) rows[idx]={vendor:envFixProduct.dataset.vendor||rows[idx].vendor,product:envFixProduct.dataset.product||rows[idx].product||''};
      saveEnvironment({...environment,products:rows});return;
    }

    const envRemoveProduct=e.target.closest('[data-remove-environment-product]');
    if(envRemoveProduct){const rows=[...(environment.products||[])];rows.splice(Number(envRemoveProduct.dataset.removeEnvironmentProduct),1);saveEnvironment({...environment,products:rows});return;}

    const envRemoveTechnology=e.target.closest('[data-remove-environment-technology]');
    if(envRemoveTechnology){const rows=[...(environment.technologies||[])];rows.splice(Number(envRemoveTechnology.dataset.removeEnvironmentTechnology),1);saveEnvironment({...environment,technologies:rows});return;}

    const envImport=e.target.closest('#environment-import-legacy');
    if(envImport&&ENV_STORE){environment=ENV_STORE.importLegacy(environment);renderEnvironmentEditor();renderExplorer();return;}

    const envClear=e.target.closest('#environment-clear');
    if(envClear){saveEnvironment(ENV_STORE?ENV_STORE.emptyProfile():{schema_version:'1.0',updated_at:null,platforms:[],products:[],technologies:[]});return;}
    const clear = e.target.closest('#clear-context');
    if (clear) { clearContext(); return; }

    const expandChips = e.target.closest('[data-expand-chips]');
    if (expandChips) {
      const chipList = expandChips.closest('.chips');
      const overflow = chipList?.querySelector('[data-chip-overflow]');
      if (overflow) {
        const willOpen = overflow.hidden;
        overflow.hidden = !willOpen;
        expandChips.setAttribute('aria-expanded', willOpen ? 'true' : 'false');
        expandChips.textContent = willOpen ? 'Show less ↑' : (expandChips.dataset.moreLabel || 'Show more');
      }
      return;
    }

    const coverageTactic = e.target.closest('[data-open-tactic]');
    if (coverageTactic) { openTacticFromCoverage(coverageTactic); return; }

    const tacticToggle = e.target.closest('[data-tactic-toggle]');
    if (tacticToggle) {
      const row = tacticToggle.closest('[data-tactic-row]');
      setTacticRowExpanded(row, tacticToggle.getAttribute('aria-expanded') !== 'true');
      return;
    }

    const expandAll = e.target.closest('[data-expand-all-tactics]');
    if (expandAll) { setAllTacticRows(expandAll.closest('.entity-card'), true); return; }

    const collapseAll = e.target.closest('[data-collapse-all-tactics]');
    if (collapseAll) { setAllTacticRows(collapseAll.closest('.entity-card'), false); return; }

    const resultScroll=e.target.closest('[data-result-scroll]');
    if(resultScroll){
      const article=resultScroll.closest('.investigation-result-entity');
      const target=article?.querySelector(`[data-result-section="${CSS.escape(resultScroll.dataset.resultScroll||'')}"]`);
      if(target){target.scrollIntoView({behavior:'smooth',block:'center'});target.classList.add('result-drill-highlight');window.setTimeout(()=>target.classList.remove('result-drill-highlight'),1100);}
      return;
    }

    const resultTacticToggle=e.target.closest('[data-toggle-result-tactics]');
    if(resultTacticToggle){
      const article=resultTacticToggle.closest('.investigation-result-entity');
      const panel=article?.querySelector('[data-result-tactics]');
      if(panel){
        const willOpen=panel.hidden;
        panel.hidden=!willOpen;
        article.querySelectorAll('[data-toggle-result-tactics]').forEach(btn=>{
          btn.setAttribute('aria-expanded',willOpen?'true':'false');
          const em=btn.querySelector('em'); if(em)em.textContent=willOpen?'閉じる ↑':'見る →';
        });
        if(willOpen)panel.scrollIntoView({behavior:'smooth',block:'nearest'});
      }
      return;
    }

    const attributeToggle=e.target.closest('[data-toggle-result-attribute]');
    if(attributeToggle){
      const article=attributeToggle.closest('.investigation-result-entity');
      const key=attributeToggle.dataset.toggleResultAttribute||'';
      const panel=article?.querySelector(`[data-result-attribute-panel="${CSS.escape(key)}"]`);
      if(panel){
        const willOpen=panel.hidden;
        panel.hidden=!willOpen;
        article.querySelectorAll(`[data-toggle-result-attribute="${CSS.escape(key)}"]`).forEach(btn=>{
          btn.setAttribute('aria-expanded',willOpen?'true':'false');
          const em=btn.querySelector('em'); if(em)em.textContent=willOpen?'閉じる ↑':'見る →';
        });
        if(willOpen)panel.scrollIntoView({behavior:'smooth',block:'nearest'});
      }
      return;
    }

    const platformRelated=e.target.closest('[data-platform-related-view]');
    if(platformRelated){
      const view=platformRelated.dataset.platformRelatedView||'techniques';
      const platform=platformRelated.dataset.platformRelatedPlatform||'';
      state.view=view; state.search=''; state.focusId=''; state.focusOnly=false; state.tactic=''; state.platform=platform;
      syncControls(); renderExplorer();
      $('explorer')?.scrollIntoView({behavior:'smooth',block:'start'});
      return;
    }

    const focusBtn = e.target.closest('[data-focus-view]');
    if (focusBtn) { focusEntity(focusBtn.dataset.focusView, focusBtn.dataset.focusId,{only:focusBtn.dataset.focusOnly==='true'}); return; }

    const relatedBtn = e.target.closest('[data-related-view]');
    if (relatedBtn) {
      const targetView = relatedBtn.dataset.relatedView || state.view;
      const hasSpecificTactic = relatedBtn.hasAttribute('data-related-tactic');
      const hasSpecificPlatform = relatedBtn.hasAttribute('data-related-platform');
      // Tactic / Platform filters are drill-down-local context. Do not silently carry
      // them into a different entity type, because that can make related counts look
      // smaller than the actual ATT&CK relationship set.
      const options = { resetContext: relatedBtn.dataset.resetContext === 'true' || targetView !== state.view };
      if (hasSpecificTactic) { options.resetContext = true; options.tactic = relatedBtn.dataset.relatedTactic || ''; }
      if (hasSpecificPlatform) { options.resetContext = true; options.platform = relatedBtn.dataset.relatedPlatform || ''; }
      jump(targetView, relatedBtn.dataset.relatedSearch||'', options);
      return;
    }

    const viewBtn = e.target.closest('#view-switch [data-view], .kpi-card[data-view]');
    if (viewBtn) {
      const view=viewBtn.dataset.view;
      jump(view,'',{resetContext:true});
      return;
    }

    const jumpBtn = e.target.closest('[data-jump-view]');
    if (jumpBtn) { jump(jumpBtn.dataset.jumpView,jumpBtn.dataset.jumpSearch||'',{resetContext:true}); return; }

    const summary = e.target.closest('.entity-summary');
    if (summary) {
      const card = summary.closest('.entity-card');
      card.classList.toggle('open');
      if (!card.classList.contains('open') && state.focusId === card.dataset.entityId) state.focusId='';
    }
  });
  $('search').addEventListener('input', e => {
    state.search=e.target.value; state.focusId=''; state.focusOnly=false;
    renderExplorer();
  });
  $('tactic-filter').addEventListener('change', e => { state.tactic=e.target.value; state.focusId=''; renderExplorer(); });
  $('platform-filter').addEventListener('change', e => { state.platform=e.target.value; state.focusId=''; renderExplorer(); });
  $('investigation-workflow').addEventListener('change',e=>{
    const box=e.target.closest('[data-environment-view-item]'); if(!box)return;
    updateScopeItem(box.dataset.environmentViewItem,box.value,box.checked);
  });
  $('environment-overlay-select')?.addEventListener('change',e=>{investigation.overlayKey=e.target.value||'none';investigation.started=false;investigation.result=null;state.focusOnly=false;const editor=$('investigation-custom-editor');if(editor)editor.open=false;saveInvestigation();});
  $('investigation-query').addEventListener('input',e=>{investigation.query=e.target.value;investigation.resolvedTarget=null;investigation.started=false;investigation.result=null;persistInvestigation();renderInvestigationWorkflow();renderInvestigationResult();});
  $('investigation-query').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();renderInvestigationWorkflow();}});
  $('my-environment').addEventListener('change', e=>{
    const box=e.target.closest('[data-environment-platform]');
    if(!box)return;
    const platforms=[...(environment.platforms||[])].filter(x=>normalize(x)!==normalize(box.value));
    if(box.checked)platforms.push(box.value);
    saveEnvironment({...environment,platforms});
  });
  $('environment-vendor-input').addEventListener('input',()=>{populateEnvironmentProductSuggestions();renderEnvironmentProductSuggestion();});
  $('environment-product-input').addEventListener('input',()=>renderEnvironmentProductSuggestion());
  $('environment-vendor-input').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();addEnvironmentProduct();}});
  $('environment-product-input').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();addEnvironmentProduct();}});
  $('environment-technology-input').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();addEnvironmentTechnology();}});
  window.addEventListener('storage',e=>{if(ENV_STORE&&e.key===ENV_STORE.KEY){environment=ENV_STORE.load();renderEnvironmentEditor();renderInvestigationWorkflow();renderExplorer();}if(e.key===INVESTIGATION_KEY){investigation=loadInvestigation();renderInvestigationWorkflow();renderInvestigationResult();renderExplorer();}if(e.key===ENV_VIEW_STORE_KEY||e.key===LEGACY_SCOPE_STORE_KEY){environmentViewStore=loadEnvironmentViewStore();renderInvestigationWorkflow();renderExplorer();}});
  window.addEventListener('scroll',updateBackToTop,{passive:true});
  window.addEventListener('resize',updateBackToTop);
  $('back-to-top')?.addEventListener('click',()=>window.scrollTo({top:0,behavior:'smooth'}));
  updateBackToTop();
}

async function init() {
  bindEvents();
  try {
    const res = await fetch(DATA_URL,{cache:'no-store'});
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    state.data = await res.json();
    buildLookups(state.data);
    environment = ENV_STORE ? ENV_STORE.load() : environment;
    applyLaunchParams();
    renderMeta(); renderKpis(); renderPanels(); populateFilters(); syncControls(); renderEnvironmentEditor(); renderInvestigationWorkflow(); renderInvestigationResult(); renderExplorer();
    if(state.focusId){window.setTimeout(()=>document.querySelector(`[data-entity-id="${CSS.escape(state.focusId)}"]`)?.scrollIntoView({behavior:'smooth',block:'start'}),120);}
  } catch (err) {
    $('load-status').textContent = 'データ読み込みエラー';
    $('data-warning').hidden = false;
    $('data-warning').innerHTML = `<strong>dashboard.jsonを読み込めませんでした。</strong><span>${esc(err.message)}</span><small>ローカル確認では file:// ではなく python -m http.server を利用してください。</small>`;
  }
}
init();
