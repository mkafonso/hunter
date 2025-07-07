# [WORK_IN_PROGRESS]

## Hunter — Similar to Lighthouse do Chrome, mas para APIs

O **Hunter** é um scanner automatizado para APIs que atua como um "Lighthouse para APIs". Ele percorre endpoints, executa validações técnicas e gera relatórios com pontuação, insights e sugestões.

> Foco em segurança, performance, estrutura, documentação e boas práticas.

---

## OpenAPI completo (Swagger v2 ou OpenAPI v3)

```bash
go run main.go scan https://petstore.swagger.io/v2/swagger.json --report=json
```

https://github.com/user-attachments/assets/a11e0951-9557-4d9e-b9ce-a5847fed3006

## Endpoint único

```bash
go run main.go scan https://viacep.com.br/ws/01001000/json/ --report=json
```

```json
{
    "score": 60,
    "issues": [
        {
            "type": "security",
            "message": "SECURITY_HEADER_MISSING",
            "path": "/ws/01001000/json/",
            "description": "A required security header is missing. These headers help protect against common vulnerabilities such as clickjacking, MIME-type sniffing, and XSS.",
            "recommendation": "Ensure headers like 'Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection', and 'Referrer-Policy' are included in responses.",
            "references": [
                "https://owasp.org/www-project-secure-headers/",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"
            ]
        },
        {
            "type": "security",
            "message": "SECURITY_CORS_CREDENTIALS_WITH_WILDCARD_ORIGIN",
            "path": "/ws/01001000/json/",
            "description": "'Access-Control-Allow-Credentials' is true while origin is '*', which is invalid per the CORS spec and creates security risks.",
            "recommendation": "Use specific origins instead of '*', or disable credentials if open access is required.",
            "references": [
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials"
            ]
        },
        {
            "type": "security",
            "message": "SECURITY_ACTIVE_RATE_LIMIT_NOT_DETECTED",
            "path": "/ws/01001000/json/",
            "description": "No rate limiting was observed — the API responded normally to multiple rapid requests.",
            "recommendation": "Implement rate limiting to prevent abuse and reduce attack surface.",
            "references": [
                "https://developer.mozilla.org/en-US/docs/Glossary/Rate_limit"
            ]
        },
        {
            "type": "structure",
            "message": "STRUCTURE_VERSIONING_MISSING_IN_PATH",
            "path": "/ws/01001000/json/",
            "description": "API routes without versioning in the path make it difficult to evolve the API without breaking existing clients.",
            "recommendation": "Include the API version in the URL path (e.g., /v1/resource) to support backward compatibility.",
            "references": ["https://restfulapi.net/versioning/"]
        }
    ]
    ...
}
```

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

## Roadmap Futuro

Não tenho plano fechado, nem mapa traçado. Irei programando as ideias que me vierem vindo, conforme o tempo, o vento e a vontade 👻
