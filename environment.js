(function(){
  'use strict';

  const KEY = 'peridotan-security-environment-v1';
  const LEGACY_KEYS = [
    'vulnerability-intelligence-watchlist-v0.9',
    'kev-dashboard-watchlist-v0.7',
    'emerging-risk-watchlist-v0.8'
  ];

  // Small built-in catalog for input normalization and suggestions only.
  // It is intentionally not an authoritative asset/product database.
  const CANONICAL_PRODUCTS = [
    {vendor:'Microsoft', product:'Windows', vendor_aliases:['microsoft','microsoft corporation','msft'], product_aliases:['windows','microsoft windows']},
    {vendor:'Microsoft', product:'Microsoft 365', vendor_aliases:['microsoft','microsoft corporation','msft'], product_aliases:['microsoft 365','m365','office 365','o365']},
    {vendor:'Microsoft', product:'Entra ID', vendor_aliases:['microsoft','microsoft corporation','msft'], product_aliases:['entra id','microsoft entra id','azure ad','azure active directory']},
    {vendor:'Microsoft', product:'Active Directory', vendor_aliases:['microsoft','microsoft corporation','msft'], product_aliases:['active directory','microsoft active directory']},
    {vendor:'VMware', product:'ESXi', vendor_aliases:['vmware','vmware by broadcom','broadcom vmware'], product_aliases:['esxi','vmware esxi']},
    {vendor:'VMware', product:'vCenter Server', vendor_aliases:['vmware','vmware by broadcom','broadcom vmware'], product_aliases:['vcenter','vcenter server','vmware vcenter','vmware vcenter server']},
    {vendor:'Apple', product:'macOS', vendor_aliases:['apple','apple inc','apple inc.'], product_aliases:['macos','mac os','os x']},
    {vendor:'Google', product:'Chrome', vendor_aliases:['google','google llc'], product_aliases:['chrome','google chrome']},
    {vendor:'Mozilla', product:'Firefox', vendor_aliases:['mozilla','mozilla foundation'], product_aliases:['firefox','mozilla firefox']}
  ];

  // Small canonical technology list for display normalization only.
  // It does not imply ATT&CK coverage or product/vulnerability applicability.
  const CANONICAL_TECHNOLOGIES = [
    {name:'PowerShell', aliases:['powershell','windows powershell','pwsh']},
    {name:'Active Directory', aliases:['active directory','microsoft active directory','ad']},
    {name:'Entra ID', aliases:['entra id','microsoft entra id','azure ad','azure active directory']},
    {name:'Microsoft 365', aliases:['microsoft 365','m365','office 365','o365']}
  ];

  const clean = value => (value ?? '').toString().trim();
  const norm = value => clean(value).toLowerCase().replace(/[®™]/g,'').replace(/[._-]+/g,' ').replace(/\s+/g,' ');
  const uniqText = values => {
    const out=[];
    for(const value of values||[]){
      const v=clean(value); if(!v) continue;
      if(!out.some(x=>norm(x)===norm(v))) out.push(v);
    }
    return out;
  };
  const uniqProducts = values => {
    const out=[];
    for(const row of values||[]){
      const vendor=clean(row?.vendor), product=clean(row?.product);
      if(!vendor) continue;
      if(!out.some(x=>norm(x.vendor)===norm(vendor)&&norm(x.product)===norm(product))) out.push({vendor,product});
    }
    return out;
  };

  const vendorMatches = (entry,value) => {
    const q=norm(value);
    if(!q) return false;
    return [entry.vendor,...(entry.vendor_aliases||[])].some(x=>norm(x)===q);
  };
  const productMatches = (entry,value) => {
    const q=norm(value);
    if(!q) return false;
    return [entry.product,...(entry.product_aliases||[])].some(x=>norm(x)===q);
  };

  function uniqueCanonicalVendors(){
    const out=[];
    for(const row of CANONICAL_PRODUCTS){if(!out.includes(row.vendor))out.push(row.vendor);}
    return out;
  }

  function analyzeProduct(vendorValue,productValue){
    const vendor=clean(vendorValue), product=clean(productValue);
    if(!vendor) return {status:'empty',input:{vendor,product},canonical:null,suggestions:[]};

    const sameVendor=CANONICAL_PRODUCTS.filter(row=>vendorMatches(row,vendor));
    if(product){
      const pairMatches=sameVendor.filter(row=>productMatches(row,product));
      if(pairMatches.length===1){
        const canonical={vendor:pairMatches[0].vendor,product:pairMatches[0].product};
        return {status:'canonical',input:{vendor,product},canonical,changed:norm(vendor)!==norm(canonical.vendor)||clean(vendor)!==canonical.vendor||norm(product)!==norm(canonical.product)||clean(product)!==canonical.product,suggestions:[canonical]};
      }

      const productOnly=CANONICAL_PRODUCTS.filter(row=>productMatches(row,product));
      if(productOnly.length===1){
        const canonical={vendor:productOnly[0].vendor,product:productOnly[0].product};
        return {status:'vendor-mismatch',input:{vendor,product},canonical,suggestions:[canonical],reason:`Product “${product}” is known under ${canonical.vendor}.`};
      }

      const fuzzy=CANONICAL_PRODUCTS.filter(row=>{
        const vq=norm(vendor), pq=norm(product);
        const vendorText=[row.vendor,...(row.vendor_aliases||[])].map(norm);
        const productText=[row.product,...(row.product_aliases||[])].map(norm);
        return vendorText.some(x=>x.includes(vq)||vq.includes(x)) || productText.some(x=>x.includes(pq)||pq.includes(x));
      }).slice(0,5).map(row=>({vendor:row.vendor,product:row.product}));
      return {status:'unknown',input:{vendor,product},canonical:null,suggestions:uniqProducts(fuzzy)};
    }

    const vendors=uniqueCanonicalVendors().filter(v=>norm(v)===norm(vendor) || CANONICAL_PRODUCTS.some(row=>row.vendor===v&&vendorMatches(row,vendor)));
    if(vendors.length===1){
      const canonical={vendor:vendors[0],product:''};
      return {status:'canonical-vendor',input:{vendor,product:''},canonical,changed:clean(vendor)!==canonical.vendor,suggestions:[canonical]};
    }
    return {status:'unknown',input:{vendor,product:''},canonical:null,suggestions:[]};
  }

  function canonicalizeProduct(row){
    const vendor=clean(row?.vendor), product=clean(row?.product);
    if(!vendor) return {vendor:'',product:''};
    const analysis=analyzeProduct(vendor,product);
    if((analysis.status==='canonical'||analysis.status==='canonical-vendor')&&analysis.canonical) return analysis.canonical;
    return {vendor,product};
  }

  function productCatalog(){
    return CANONICAL_PRODUCTS.map(row=>({vendor:row.vendor,product:row.product}));
  }

  function analyzeTechnology(value){
    const input=clean(value);
    if(!input) return {status:'empty',input:'',canonical:'',changed:false};
    const q=norm(input);
    const hit=CANONICAL_TECHNOLOGIES.find(row=>[row.name,...(row.aliases||[])].some(x=>norm(x)===q));
    if(!hit) return {status:'unknown',input,canonical:input,changed:false};
    return {status:'canonical',input,canonical:hit.name,changed:input!==hit.name};
  }

  function canonicalizeTechnology(value){
    const a=analyzeTechnology(value);
    return a.canonical||clean(value);
  }

  function emptyProfile(){
    return {schema_version:'1.0',updated_at:null,platforms:[],products:[],technologies:[]};
  }

  function sanitize(raw){
    const base=emptyProfile();
    if(!raw||typeof raw!=='object') return base;
    return {
      schema_version:'1.0',
      updated_at: clean(raw.updated_at)||null,
      platforms: uniqText(raw.platforms),
      products: uniqProducts((raw.products||[]).map(canonicalizeProduct)),
      technologies: uniqText((raw.technologies||[]).map(canonicalizeTechnology))
    };
  }

  function load(){
    try{
      const raw=localStorage.getItem(KEY);
      return raw?sanitize(JSON.parse(raw)):emptyProfile();
    }catch{return emptyProfile();}
  }

  function save(profile){
    const next=sanitize(profile);
    next.updated_at=new Date().toISOString();
    localStorage.setItem(KEY,JSON.stringify(next));
    window.dispatchEvent(new CustomEvent('peridotan-environment-change',{detail:next}));
    return next;
  }

  function readLegacyWatchlist(){
    const out=[];
    for(const key of LEGACY_KEYS){
      try{
        const rows=JSON.parse(localStorage.getItem(key)||'[]')||[];
        for(const row of rows){
          const vendor=clean(row?.vendor), product=clean(row?.product);
          if(!vendor) continue;
          const canonical=canonicalizeProduct({vendor,product});
          if(!out.some(x=>norm(x.vendor)===norm(canonical.vendor)&&norm(x.product)===norm(canonical.product))) out.push(canonical);
        }
      }catch{}
    }
    return out;
  }

  function importLegacy(profile){
    const current=sanitize(profile||load());
    current.products=uniqProducts([...(current.products||[]),...readLegacyWatchlist()]);
    return save(current);
  }

  window.PeridotanEnvironment={
    KEY,LEGACY_KEYS,CANONICAL_PRODUCTS,CANONICAL_TECHNOLOGIES,
    emptyProfile,sanitize,load,save,readLegacyWatchlist,importLegacy,
    analyzeProduct,canonicalizeProduct,productCatalog,analyzeTechnology,canonicalizeTechnology,norm
  };
})();
