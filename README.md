# Sentinel — Auditoria externa para Vercel

Aplicação web responsiva com função serverless `/api/scan`, pronta para deploy na Vercel.

## O que verifica
- Resolução DNS e conexão HTTPS do domínio público.
- Cabeçalhos HTTP relevantes, apresentados como observações (não como críticas automáticas).
- Exposições públicas com evidência de conteúdo em `/.env`, `/.git/config`, `/backup.zip` e `/database.sql`.
- Resumo técnico em português via Gemini API, quando a chave está configurada.
- Exportação do relatório em JSON.

## Limites técnicos
A análise é externa, limitada e não intrusiva: requisições GET, sem login, força bruta, exploração, upload, alteração ou varredura de portas. O conjunto de caminhos verificados é pequeno e explícito. Um resultado sem achados não prova que o domínio esteja seguro. Para auditoria empresarial completa, complemente com SAST, DAST autenticado autorizado, revisão de código e testes especializados.

## Publicar na Vercel
1. Extraia o ZIP e envie a pasta para um repositório Git ou importe-a na Vercel.
2. Em **Project → Settings → Environment Variables**, adicione:
   - `GEMINI_API_KEY`: sua chave da API Gemini.
   - `GEMINI_MODEL`: opcional; padrão `gemini-2.5-flash`.
3. Faça o deploy. A Vercel publica `index.html` e disponibiliza automaticamente a rota `POST /api/scan` pelo arquivo `api/scan.js`.
4. Abra o domínio publicado, informe um domínio que você tem autorização para auditar e marque a confirmação.

## Testar localmente
Requer Node.js 20+ e Vercel CLI:
```bash
npm install
npx vercel dev
```

## Custos Gemini
A chave fica exclusivamente no servidor Vercel, nunca no navegador. O Gemini é chamado uma vez por auditoria. Configure limites e alertas de uso no Google AI Studio/Google Cloud. A aplicação não promete encontrar todas as vulnerabilidades críticas e não inventa achados.

## Segurança operacional
- Não coloque a chave no `index.html`, `app.js` ou no Git.
- Não remova a validação de destinos públicos nem o bloqueio de redirecionamentos.
- O limite de requisições deve ser reforçado com rate limiting externo em produção (por exemplo, proteção da plataforma/WAF); memória local da função serverless não é um limitador confiável.
- Use somente em domínios sob sua propriedade ou com autorização documentada.
