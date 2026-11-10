const form=document.querySelector("#scan-form"),button=document.querySelector("#scan-button"),progress=document.querySelector("#progress-wrap"),results=document.querySelector("#results");
let latestReport=null;
const $=s=>document.querySelector(s);
function showError(message){let box=$("#scan-error");box.hidden=false;box.textContent=message;}
function esc(v=""){return String(v).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function render(report){
 latestReport=report;const findings=report.findings||[],obs=report.observations||[];
 $("#critical-count").textContent=findings.filter(x=>x.severity==="CRITICAL").length;
 $("#finding-state").textContent=findings.length?"ACHADOS CONFIRMADOS":"SEM EXPOSIÇÃO CONFIRMADA";
 $("#checks-count").textContent=report.checks_run??0;
 $("#https-status").textContent=report.https?.ok?"OK":"FALHA";
 $("#https-detail").textContent=report.https?.ok?"TLS validado":"HTTPS não validado";
 $("#scan-meta").textContent=`${report.domain} · ${new Date(report.generated_at).toLocaleString("pt-BR")}`;
 $("#findings").innerHTML=findings.length?findings.map(f=>`<article class="finding"><div class="finding-top"><div><h4>${esc(f.title)}</h4><p>${esc(f.description)}</p></div><span class="severity">${esc(f.severity||"HIGH")}</span></div><p><b>Impacto:</b> ${esc(f.impact)}</p><div class="evidence">${esc(f.evidence)}</div><p><b>Correção:</b> ${esc(f.remediation)}</p></article>`).join(""):`<div class="empty">Nenhuma exposição crítica foi confirmada nas verificações executadas.</div>`;
 $("#observations").innerHTML=obs.length?obs.map(o=>`<div class="finding"><h4>${esc(o.title)}</h4><p>${esc(o.detail)}</p></div>`).join(""):`<div class="empty">Nenhuma observação adicional.</div>`;
 $("#ai-summary").textContent=report.ai_summary||"Resumo por IA indisponível. Consulte as evidências técnicas acima.";
 if(report.limitations) $(".disclaimer").textContent=report.limitations;
 results.hidden=false;results.scrollIntoView({behavior:"smooth",block:"start"});
}
form.addEventListener("submit",async e=>{
 e.preventDefault();$("#scan-error").hidden=true;if(!$("#authorized").checked)return;
 const domain=$("#domain").value.trim();button.disabled=true;button.querySelector("span").textContent="Analisando...";progress.hidden=false;results.hidden=true;
 $("#progress-text").textContent="Verificando DNS, HTTPS e exposições públicas...";
 try{
  const health=await fetch("/api/health",{method:"GET",cache:"no-store"});
  if(!health.ok)throw new Error("A API da Sentinel não foi publicada corretamente. Na Vercel, defina Root Directory como sentinel-v2 e faça Redeploy.");
  const healthData=await health.json();if(!healthData.ok)throw new Error("A API respondeu, mas não confirmou o serviço Sentinel.");
  const res=await fetch("/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domain}),cache:"no-store"});
  const raw=await res.text();let data;try{data=JSON.parse(raw)}catch{throw new Error(`A função de auditoria retornou resposta inválida (HTTP ${res.status}). Verifique Runtime Logs na Vercel.`)}
  if(!res.ok)throw new Error(data.error||`Falha na auditoria (HTTP ${res.status}).`);
  render(data);
 }catch(err){
  const msg=err instanceof TypeError&&/fetch/i.test(err.message)?"Falha de conexão com a API. Confira se /api/health abre no mesmo domínio e se o deploy terminou sem erro.":(err.message||"Falha inesperada.");
  showError(msg);
 }
 finally{button.disabled=false;button.querySelector("span").textContent="Executar análise";progress.hidden=true;}
});
$("#download-report").addEventListener("click",()=>{
 if(!latestReport)return;const blob=new Blob([JSON.stringify(latestReport,null,2)],{type:"application/json"}),url=URL.createObjectURL(blob),a=document.createElement("a");
 a.href=url;a.download=`sentinel-audit-${latestReport.domain.replace(/[^a-z0-9.-]/gi,"_")}.json`;a.click();URL.revokeObjectURL(url);
});