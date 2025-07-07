# [WORK_IN_PROGRESS]

## Hunter — Similar to Lighthouse do Chrome, mas para APIs

O **Hunter** é um scanner automatizado para APIs que atua como um "Lighthouse para APIs". Ele percorre endpoints, executa validações técnicas e gera relatórios com pontuação, insights e sugestões.

> Foco em segurança, performance, estrutura, documentação e boas práticas.

---

## Funcionalidades

### ✅ Segurança

-   [x] Verificação de headers de segurança ausentes (`Strict-Transport-Security`, `X-Content-Type-Options`, etc.)
-   [x] CORS permissivo (`Access-Control-Allow-Origin: *`)
-   [x] Exposição de headers sensíveis (`X-Powered-By`, `Server`, etc.)
-   [x] Rate limiting passivo (headers `X-RateLimit-*`, `Retry-After`)
-   [x] Rate limiting ativo (respostas `429` após burst de requisições)

### ✅ Performance

-   [x] Tempo de resposta (latência > 500ms)
-   [x] Tamanho excessivo de payloads
-   [x] Ausência de compressão (`Content-Encoding`)

### ✅ Estrutura da API

-   [x] Status codes inconsistentes (ex: `200 OK` para erros)
-   [x] Métodos HTTP incorretos (ex: `GET` retornando `201`)
-   [x] Ausência de versionamento na URL (ex: `/v1/`)
-   [x] Inconsistência de casing nos campos do JSON (ex: `camelCase` e `snake_case` no mesmo JSON)

### ✅ Vulnerabilidades

-   [x] Exposição de stacktraces ou mensagens sensíveis em erros

---

## Estrutura do Projeto

## Roadmap Futuro
