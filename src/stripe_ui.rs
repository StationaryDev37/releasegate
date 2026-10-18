//! Dependency-free, same-origin developer checkout and signed receipt delivery pages.
use axum::{http::{header, HeaderMap, HeaderValue}, response::{Html, IntoResponse}};

const BUY: &str = r##"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ReleaseGate — Verified Release</title><style>
:root{color-scheme:dark;font-family:system-ui,-apple-system,sans-serif;background:#0b1020;color:#f0f4ff}
body{max-width:760px;margin:auto;padding:6vw 22px;line-height:1.6}
h1{font-size:clamp(2.2rem,7vw,4.2rem);line-height:1.04;margin:24px 0}h1 span{color:#8bd6ff}
.panel{border:1px solid #31425b;border-radius:18px;padding:26px;background:#131c30;margin:24px 0}
label{display:block;font-weight:650;margin:20px 0 8px}input{box-sizing:border-box;width:100%;padding:14px;border-radius:9px;border:1px solid #60718a;background:#0b1020;color:white;font-size:17px}
button{padding:15px 23px;background:#83dbd0;border:none;border-radius:9px;color:#091523;font-size:18px;font-weight:800;cursor:pointer;margin-top:16px}
small,.muted{color:#b5c3d5}#error{color:#ffafaf}strong.price{font-size:32px}
</style></head><body>
<p class="muted">KINHOLD / RELEASEGATE</p><h1>A signed release decision.<br><span>Not a promise of approval.</span></h1>
<p>Verify GitHub artifact provenance against the repository's authenticated source events, a frozen release policy and Sigstore evidence. Receive a cryptographically signed decision and auditable receipt.</p>
<div class="panel"><strong class="price">$29</strong> <span class="muted">USD · one evaluation · no subscription</span>
<p>Truthful outcomes are <b>RELEASE</b>, <b>HOLD</b>, or <b>BLOCK</b>. Payment never buys a guaranteed RELEASE.</p>
<form id="purchase"><label for="installation">Your ReleaseGate GitHub App installation ID</label><input id="installation" name="installation" type="number" min="1" required>
<small>Install the ReleaseGate GitHub App on the repository first. Your installation must already have been recorded from an authenticated GitHub event.</small>
<button type="submit">Continue to secure Stripe checkout →</button><p id="error" role="alert"></p></form>
</div><p class="muted">Payments are processed by Stripe. No custody of your assets, code secrets or wallet funds. Results are determined by signed evidence, not the payment.</p>
<script>
const form=document.getElementById('purchase');form.addEventListener('submit',async(e)=>{
e.preventDefault();let b=form.querySelector('button');b.disabled=true;
try{const id=document.getElementById('installation').value;const r=await fetch('/v1/checkout/link/'+encodeURIComponent(id),{cache:'no-store'});if(!r.ok)throw Error('No active ReleaseGate installation was found for that ID.');const v=await r.json();if(!v.purchase_url.startsWith('https://buy.stripe.com/'))throw Error('Unexpected payment destination');location.href=v.purchase_url;}catch(err){document.getElementById('error').textContent=err.message;b.disabled=false;}
});
</script></body></html>"##;

const RECEIPT: &str = r##"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ReleaseGate — Your verification</title><style>
:root{color-scheme:dark;font-family:system-ui;background:#0b1020;color:#f0f4ff}
body{max-width:780px;margin:auto;padding:30px 18px;line-height:1.5}
.panel{border:1px solid #31425b;border-radius:14px;padding:22px;background:#131c30}
label{display:block;margin:12px 0 5px}input,select{width:100%;box-sizing:border-box;padding:10px;border:1px solid #64748b;border-radius:7px;background:#0b1020;color:white}
button{padding:12px 18px;background:#83dbd0;color:#06151d;border:0;border-radius:8px;margin-top:18px;font-weight:bold;cursor:pointer}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#070b15;padding:15px;border-radius:9px}
.muted{color:#b8c5d7}
</style></head><body><h1>Your verified release</h1><p id="status" aria-live="polite">Checking payment confirmation…</p>
<section class="panel" id="form-wrap" hidden><p>Stripe has confirmed the payment. Enter the repository and trusted workflow facts for this evaluation. The result may RELEASE, HOLD or BLOCK.</p>
<form id="run"><label>Repository ID<input required name="repository_id" inputmode="numeric"></label><label>Repository owner/name<input required name="repository"></label>
<label>Source ref<input required name="source_ref" value="refs/heads/main"></label><label>Source commit SHA<input required name="source_commit_sha" minlength="40" maxlength="40"></label>
<label>Artifact SHA-256<input required name="artifact_sha256" minlength="64" maxlength="64"></label>
<label>Trusted signer workflow path<input required name="signer_workflow_path"></label><label>Signer revision commit SHA<input required name="signer_revision_sha" minlength="40" maxlength="40"></label>
<button type="submit">Verify and issue signed decision</button></form></section><pre id="receipt" hidden></pre>
<script>
let session=new URLSearchParams(location.hash.slice(1)).get('session_id')||sessionStorage.getItem('rg_paid_session');if(session)sessionStorage.setItem('rg_paid_session',session);history.replaceState(null,'',location.pathname);const status=document.getElementById('status');const block=document.getElementById('form-wrap');const output=document.getElementById('receipt');let installation=0;
async function post(path,data){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data),cache:'no-store'});const v=await r.json();if(!r.ok)throw Error(v.message||v.error||('HTTP '+r.status));return v;}
async function check(){if(!session||!/^cs_live_[A-Za-z0-9_]+$/.test(session)){status.textContent='Missing valid Checkout Session identifier';return;}
for(let i=0;i<12;i++){try{let v=await post('/v1/orders',{session_id:session});if(v.result){status.textContent='Signed decision delivered';output.hidden=false;output.textContent=JSON.stringify(v.result,null,2);return;}
if(v.payment_state==='revoked'){status.textContent='This purchase has been revoked';return;}installation=v.installation_id;if(v.payment_state==='paid'&&Number.isSafeInteger(installation)&&installation>0){status.textContent='Payment confirmed · enter your repository evidence';block.hidden=false;return;}
}catch(e){if(i===11){status.textContent='Payment not yet recorded: '+e.message;return;}}
await new Promise(r=>setTimeout(r,1500));}status.textContent='Payment may still be processing. Reload this page after Stripe confirms it.';}
check();document.getElementById('run').addEventListener('submit',async(e)=>{e.preventDefault();const values=Object.fromEntries(new FormData(e.target));const repo=values.repository;const policy={session_id:session,installation_id:installation,repository_id:Number(values.repository_id),repository:repo,ref_rule:'exact',ref_value:values.source_ref,signer_repository:repo,signer_workflow_path:values.signer_workflow_path,signer_revision_sha:values.signer_revision_sha};status.textContent='Checking authorized release policy…';
try{await post('/v1/policies/paid',policy);status.textContent='Verifying signed provenance…';const result=await post('/v1/evaluations/paid',{session_id:session,installation_id:installation,repository_id:Number(values.repository_id),source_commit_sha:values.source_commit_sha,source_ref:values.source_ref,artifact_sha256:values.artifact_sha256});status.textContent='Verification complete. Preserve the signed receipt below.';block.hidden=true;output.hidden=false;output.textContent=JSON.stringify(result,null,2);}catch(e){status.textContent='Verification not completed: '+e.message;}});
</script></body></html>"##;

fn security_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert("content-security-policy", HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"));
    headers
}

pub async fn buy() -> impl IntoResponse { (security_headers(), Html(BUY)) }
pub async fn receipt() -> impl IntoResponse { (security_headers(), Html(RECEIPT)) }
