import dns from "node:dns/promises";
import net from "node:net";

const PATHS = [
  { path: "/.env", label: "Arquivo .env publicamente acessível", marker: /(?:DB_PASSWORD|DATABASE_URL|AWS_SECRET_ACCESS_KEY|API_KEY|SECRET_KEY)\s*=/i },
  { path: "/.git/config", label: "Configuração interna do Git exposta", marker: /^\s*\[core\]/im },
  { path: "/backup.zip", label: "Backup compactado publicamente acessível", marker: null },
  { path: "/database.sql", label: "Dump SQL publicamente acessível", marker: /^\s*(?:CREATE TABLE|INSERT INTO|-- MySQL)/im }
];
const PRIVATE = ip => {
  if (net.isIPv4(ip)) {
    const p=ip.split(".").map(Number);
    return p[0]===10 || p[0]===127 || p[0]===0 || p[0]>=224 ||
      (p[0]===169&&p[1]===254) || (p[0]===172&&p[1]>=16&&p[1]<=31) ||
      (p[0]===192&&p[1]===168) || (p[0]===100&&p[1]>=64&&p[1]<=127);
  }
  if (net.isIPv6(ip)) {
    const x=ip.toLowerCase();
    return x==="::1" || x==="::" || x.startsWith("fc") || x.startsWith("fd") ||
      x.startsWith("fe80:") || x.startsWith("::ffff:127.") || x.startsWith("::ffff:10.");
  }
  return true;
};
function normalizeDomain(input) {
  if(typeof input!=="string" || input.length>300) throw new Error("Informe um domínio válido.");
  let u; try { u=new URL(input.includes("://")?input:`https://${input}`); } catch { throw new Error("Domínio inválido."); }
  if(!["http:","https:"].includes(u.protocol) || u.username || u.password || u.port && !["80","443"].includes(u.port))
    throw new Error("Use um domínio público HTTP/HTTPS, sem credenciais ou portas alternativas.");
  const host=u.hostname.toLowerCase().replace(/\.$/,"");
  if(!host || host==="localhost" || host.endsWith(".localhost") || net.isIP(host)) throw new Error("Informe um nome de domínio público, não um IP ou endereço local.");
  return {host, origin:`https://${host}`};
}
async function assertPublicHost(host) {
  const records=await dns.lookup(host,{all:true,verbatim:true});
  if(!records.length || records.some(r=>PRIVATE(r.address))) throw new Error("O domínio resolve para endereço não público; auditoria bloqueada.");
}
async function safeGet(url, host, maxBytes=12000) {
  const parsed=new URL(url);
  if(parsed.hostname!==host || !["https:"].includes(parsed.protocol)) throw new Error("Destino externo bloqueado.");
  const controller=new AbortController(), timer=setTimeout(()=>controller.abort(),6500);
  try {
    const response=await fetch(url,{method:"GET",redirect:"manual",signal:controller.signal,
      headers:{"User-Agent":"Sentinel-External-Audit/1.0","Range":`bytes=0-${maxBytes-1}`,"Accept":"*/*"}});
    if(response.status>=300&&response.status<400) return {status:response.status,redirect:true,headers:response.headers,body:""};
    const reader=response.body?.getReader();let body="",size=0;
    if(reader){while(size<maxBytes){const {done,value}=await reader.read();if(done)break;const part=value.subarray(0,maxBytes-size);body+=new TextDecoder().decode(part);size+=part.length;if(part.length<value.length)break;}await reader.cancel().catch(()=>{});}
    return {status:response.status,redirect:false,headers:response.headers,body};
  } finally {clearTimeout(timer);}
}
async function geminiSummary(domain, findings, observations) {
  const key=process.env.GEMINI_API_KEY;
  if(!key) return "GEMINI_API_KEY não configurada. O relatório técnico continua disponível sem resumo por IA.";
  const prompt=`Você é analista de segurança defensiva. Resuma em português, sem inventar fatos. Diferencie evidência confirmada de observação. Não eleve severidade sem evidência. Domínio: ${domain}. Achados confirmados: ${JSON.stringify(findings)}. Observações: ${JSON.stringify(observations)}. Gere no máximo 130 palavras com prioridade de correção.`;
  const model=process.env.GEMINI_MODEL||"gemini-2.5-flash";
  const response=await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,{
    method:"POST",headers:{"Content-Type":"application/json","x-goog-api-key":key},
    body:JSON.stringify({contents:[{parts:[{text:prompt}]}],generationConfig:{temperature:0.1,maxOutputTokens:240}})
  });
  if(!response.ok) throw new Error("Gemini indisponível");
  const data=await response.json();
  return data.candidates?.[0]?.content?.parts?.map(p=>p.text||"").join("").slice(0,1800)||"Resumo indisponível.";
}
export default async function handler(req,res) {
  res.setHeader("Cache-Control","no-store");
  if(req.method!=="POST"){res.setHeader("Allow","POST");return res.status(405).json({error:"Método não permitido."});}
  try {
    const {host}=normalizeDomain(req.body?.domain);
    await assertPublicHost(host);
    const findings=[],observations=[];let checks=0,https={ok:false};
    try {
      const main=await safeGet(`https://${host}/`,host);checks++;
      https={ok:main.status>0 && !main.redirect,status:main.status};
      const h=main.headers;
      if(!h.get("strict-transport-security")) observations.push({title:"HSTS ausente",detail:"A resposta HTTPS não apresentou Strict-Transport-Security. Isso merece revisão, mas isoladamente não comprova vulnerabilidade crítica."});
      if(!h.get("content-security-policy")) observations.push({title:"CSP ausente",detail:"A página não apresentou Content-Security-Policy. Avalie uma política compatível com os recursos do site."});
      if(!h.get("x-content-type-options")) observations.push({title:"X-Content-Type-Options ausente",detail:"Considere configurar nosniff para reduzir interpretação incorreta de tipos MIME."});
      const server=h.get("server");if(server)observations.push({title:"Cabeçalho Server",detail:`O servidor divulga o identificador: ${server.slice(0,120)}.`});
    } catch(e) { observations.push({title:"HTTPS não validado",detail:"A conexão HTTPS não pôde ser validada: "+String(e.message).slice(0,180)}); }
    for(const item of PATHS) {
      checks++;
      try {
        const r=await safeGet(`https://${host}${item.path}`,host,12000);
        if(r.status===200 && !r.redirect) {
          const type=(r.headers.get("content-type")||"").toLowerCase();
          const body=r.body||"";
          const confirmed=item.marker ? item.marker.test(body) : (item.path.endsWith(".zip") ? (type.includes("zip")||body.startsWith("PK")) : (type.includes("sql")||/CREATE TABLE|INSERT INTO/i.test(body)));
          if(confirmed) findings.push({
            title:item.label,severity:"CRITICAL",
            description:`O caminho ${item.path} respondeu HTTP 200 e apresentou conteúdo compatível com o artefato esperado.`,
            impact:"Pode permitir acesso não autenticado a configurações, código interno, cópias de segurança ou dados armazenados.",
            evidence:`GET ${item.path} → HTTP 200; Content-Type: ${(type||"não informado").slice(0,100)}; marcador de conteúdo confirmado.`,
            remediation:"Remova o arquivo da raiz pública, bloqueie o acesso no servidor, invalide credenciais potencialmente expostas e revise os logs de acesso."
          });
        }
      } catch {}
    }
    let ai_summary;
    try { ai_summary=await geminiSummary(host,findings,observations); } catch { ai_summary="A análise Gemini falhou nesta execução. As evidências técnicas permanecem disponíveis acima."; }
    return res.status(200).json({domain:host,generated_at:new Date().toISOString(),checks_run:checks,https,findings,observations,ai_summary,
      scope:"Verificações externas, GET limitado, sem autenticação, exploração ou alteração de dados."});
  } catch(e) { return res.status(400).json({error:e.message||"Não foi possível executar a auditoria."}); }
}