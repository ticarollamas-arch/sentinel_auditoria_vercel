# Sentinel 3.0 — auditoria externa baseada em evidências

## Correção do Failed to fetch

Esta versão inclui `/api/health` para confirmar que as funções serverless foram publicadas, mensagens de erro legíveis no painel e timeouts menores com concorrência controlada para reduzir falhas por duração da função.

**Configuração importante na Vercel:** em Project Settings → General → Root Directory, selecione `sentinel-v2` (ou importe diretamente essa pasta como projeto). Depois faça Redeploy. A pasta `api` precisa ficar diretamente dentro da raiz publicada.

Teste a API abrindo `https://SEU-DOMINIO/api/health`. Deve aparecer JSON com `"ok": true`. Se retornar 404, a Root Directory está incorreta ou o deploy ainda não publicou as funções.

## Variáveis opcionais de IA

- OpenAI: `OPENAI_API_KEY`; opcional `OPENAI_MODEL` (padrão `gpt-6-luna`).
- Gemini: `GEMINI_API_KEY`; opcional `GEMINI_MODEL` (padrão `gemini-2.5-flash`).
- Se ambas existirem, OpenAI tem prioridade. A IA só interpreta o relatório; não determina nem inventa achados.

## Execução local

Node.js 20+: `npm install` e `npx vercel dev`.

## Limites

Somente domínios próprios ou autorizados. Requisições HTTPS GET para caminhos públicos conhecidos, sem autenticação, exploração, força bruta, upload, alteração de dados ou varredura de portas. As verificações têm timeout de 2,2 segundos e concorrência limitada. Achados críticos exigem evidência compatível; ausência de achados não comprova segurança. Para cobertura completa, complemente com DAST autenticado autorizado, SAST, revisão de código e pentest.
