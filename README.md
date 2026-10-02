# 🛡️ Automated Security Auditor — Framework de Reconhecimento e Auditoria de Superfície de Ataque

Framework modular em Python para **auditoria automatizada de postura de segurança externa e testes de intrusão autorizados**, avaliando parâmetros de rede, cabeçalhos de segurança web (OWASP), integridade de certificados SSL/TLS e configurações de DNS contra superfícies de ataque públicas.

Gera relatórios executivos em Markdown e JSON estruturado com classificação de risco conforme o padrão **CVSS v3.1**.

---

## ⚠️ Aviso Legal / Authorized Use Only

> **IMPORTANTE:** Esta ferramenta foi desenvolvida exclusivamente para auditorias em infraestruturas e domínios **próprios ou expressamente autorizados por escrito**. Qualquer uso não autorizado contra alvos de terceiros é estritamente proibido e ilegal. O autor não se responsabiliza pelo uso indevido deste software.

---

## 📌 Que Problema Resolve?

Muitas organizações expõem involuntariamente aplicações com:
- Falta de cabeçalhos de proteção essenciais (ex: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`), facilitando ataques de Clickjacking e XSS.
- Certificados SSL/TLS com cifras fracas (TLS 1.0/1.1 ativas) ou próximos da expiração.
- Vazamento de versões de servidores web (`Server`, `X-Powered-By`) que auxiliam invasores na identificação de exploits conhecidos.
- Registros de DNS mal configurados que permitem sequestro de subdomínios (Subdomain Takeover).

O **Automated Security Auditor** automatiza essa verificação em segundos, fornecendo um diagnóstico acionável antes que agentes maliciosos explorem as brechas.

---

## ⚙️ Módulos de Auditoria

1. **Módulo de Cabeçalhos HTTP / OWASP:**
   - Validação de `HSTS` com diretiva `includeSubDomains`.
   - Inspeção de `CSP` (Content Security Policy) para detecção de diretivas permissivas (`unsafe-inline`, `*`).
   - Verificação de políticas de cookies (`SameSite`, `Secure`, `HttpOnly`).
2. **Módulo SSL / TLS:**
   - Negociação de cifras e protocolos suportados.
   - Cálculo de dias restantes até expiração do certificado X.509.
   - Validação da cadeia de autoridade certificadora (CA Chain).
3. **Módulo DNS & Superfície:**
   - Resolução de registros MX, TXT (SPF, DKIM, DMARC para prevenção de spoofing de e-mail).
   - Detecção de registros CNAME órfãos apontando para serviços em nuvem desativados.

---

## 🏗️ Stack Tecnológica

- **Linguagem:** Python 3.10+
- **Bibliotecas:** `dnspython`, `cryptography`, `urllib3`, `rich` (CLI formatada e colorida).
- **Saída:** Relatórios executivos padronizados em Markdown e JSON.

---

## 🚀 Como Executar Localmente

```bash
# 1. Clone o repositório
git clone https://github.com/HenriMafra/automated-security-auditor.git
cd automated-security-auditor

# 2. Crie e ative o ambiente virtual
python -m venv venv
source venv/bin/activate  # No Windows: .\venv\Scripts\activate

# 3. Instale as dependências
pip install -r requirements.txt

# 4. Execute a auditoria em um domínio autorizado
python -m aegis.cli scan --target example.com --output relatorio.md
```

---

## 📄 Licença

Distribuído sob a licença **MIT**. Desenvolvido por **Henri Mafra**.
