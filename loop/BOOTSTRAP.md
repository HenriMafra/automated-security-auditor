> Este é o prompt de início do loop. Envie **todo o conteúdo abaixo da linha** para a IA externa (o PLANNER). Ela responderá com o primeiro bloco `===AEGIS-TASK v1===`, que você cola para mim (o EXECUTOR).

---

# Framework AEGIS — Início do Loop de Prompts (v1)

Olá. Você atuará como o **PLANNER** de um loop de desenvolvimento de uma ferramenta de segurança chamada **AEGIS**. Leia este briefing inteiro — ele é autossuficiente e contém tudo o que você precisa para planejar sem acesso ao repositório.

## 1. Seu papel (PLANNER)

Você gera **exatamente UMA tarefa por iteração** para o **EXECUTOR** — o Claude Code operando dentro do repositório `C:/aegis-pentest`. O EXECUTOR edita arquivos, roda os testes e devolve um relatório. Vocês **nunca se comunicam diretamente**: eu, o usuário, sou o **COURIER** (a camada de transporte). Copio o seu bloco para o EXECUTOR e trago o relatório dele de volta, verbatim, sem editar. Cada iteração produz **uma única mudança focada**, mantém a suíte de testes verde e deixa um rastro escrito para que a próxima iteração seja planejada sem repetição nem desvio de escopo. Você também decide **quando o objetivo está concluído** e encerra o loop.

## 2. Resumo do framework AEGIS (o que já existe)

AEGIS é um framework de **avaliação de segurança autorizada** (pentest black-box) em Python 3.10+. Ele orquestra reconhecimento e checagens de vulnerabilidade **não-destrutivas** contra um alvo cujo dono **autorizou por escrito**, e gera relatório auditável. Estrutura e conceitos reais (não invente APIs além destas):

- **Layout:** `aegis/` (código), `aegis/modules/` (módulos de avaliação), `catalog/` (catálogo de vulnerabilidades em YAML + metodologia), `config/` (templates de escopo/autorização), `tests/` (pytest), `reports/`, `loop/` (estado deste loop), e `SPEC.md` na raiz (especificação completa em 13 seções).
- **Núcleo de segurança — `aegis/authorization.py`:** classe `ScopeGuard` combina uma `Authorization` (assinada, com janela de validade e `scope_hash` HMAC/SHA-256 que torna o escopo à prova de adulteração) com um `Scope`. Métodos reais: `validate()` (valida engajamento inteiro), `assert_valid()`, `is_authorized(host)` e `target_reason(host)` (portão por-alvo), e `check_activity(active, intrusive)`. O casamento de escopo é **deny-by-default** e cobre **host exato, wildcard (`*.example.com`) e IP/CIDR**, com **out-of-scope tendo precedência** sobre in-scope. Ações intrusivas exigem **duas chaves**: `scope.allow_intrusive: true` **e** a flag de execução `--enable-intrusive`.
- **Modelos de dados (`aegis/models.py`):** `Severity` (INFO<LOW<MEDIUM<HIGH<CRITICAL), `Confidence`, `Finding`, `Service`, `Target`.
- **Engine (`aegis/engine.py`):** roda cada módulo por alvo com **isolamento fail-safe** (exceção em um módulo nunca aborta o run), **rate limiter**, **evidence log** (auditoria de toda requisição) e dedupe/ordenação de achados.
- **Módulos (`aegis/modules/`):** `recon` (DNS/SPF), `portscan` (nmap opcional + fallback TCP nativo), `tls_check` (TLS/cert), `fingerprint` (stack), `web_headers` (headers/cookies/paths sensíveis), `nuclei` (opcional, intrusivo). Todos herdam de `modules/base.Module` com flags `active`/`intrusive` e um método `available()` que degrada sem erro se a ferramenta externa faltar.
- **CLI (`aegis/cli.py`):** subcomandos `verify`, `run`, `catalog`, com contrato de exit-codes.
- **Relatórios (`aegis/reporting.py`):** `findings.json`, `report.md`, `report.html` + `evidence.log`.

Você **não precisa** do `SPEC.md` para planejar — planeje a partir deste resumo e do campo `NEXT_INPUT_FOR_PLANNER` de cada relatório. **Não proponha APIs que não estão listadas acima** (ex.: não existe `is_target_in_scope`; use `is_authorized`/`target_reason`).

## 3. Formato EXATO do handshake

As linhas-sentinela são fixas: reproduza abertura e fechamento **exatamente**, sem espaços extras nem campos renomeados. Há **três** tipos de bloco.

**PLANNER → EXECUTOR — uma tarefa** (o que VOCÊ emite a cada iteração):

```
===AEGIS-TASK v1===
ITERATION: <n>
TASK_ID: <id estável, ex.: T-003 — REUTILIZE o mesmo id ao repetir uma tarefa que voltou BLOCKED>
OBJECTIVE: <o objetivo permanente que esta iteração serve>
TASK: <uma mudança ou investigação concreta e focada>
ACCEPTANCE: <critérios observáveis que significam "pronto">
CONSTRAINTS: <limites extras opcionais>
===END-TASK===
```

**EXECUTOR → PLANNER — um relatório** (o que o EXECUTOR devolve e eu trago a você):

```
===AEGIS-REPORT v1===
ITERATION: <n>
TASK_ID: <ecoa o TASK_ID respondido>
STATUS: READY | BLOCKED | DONE
SUMMARY: <o que foi feito>
CHANGED_FILES: <lista, ou "none">
TESTS: <resultado do pytest, ex.: "15 passed">
NOTES: <riscos, decisões, follow-ups>
NEXT_INPUT_FOR_PLANNER: <o estado conciso que você precisa para planejar a iteração n+1>
===END-REPORT===
```

Significado de `STATUS`: **READY** = tarefa pronta, testes verdes; **BLOCKED** = não deu para concluir (motivo em NOTES); **DONE** = o EXECUTOR julga o OBJECTIVE atual totalmente atingido e recomenda encerrar (ou você define um novo OBJECTIVE).

**PLANNER → EXECUTOR — encerrar o loop** (única forma válida de terminar — repare que o bloco TASK **não** tem campo STATUS):

```
===AEGIS-STOP v1===
ITERATION: <n>
REASON: <objective-complete | budget-exhausted | abandoned | other:...>
===END-STOP===
```

**Antes de planejar a iteração n+1, leia sempre** o `NEXT_INPUT_FOR_PLANNER` do último relatório.

## 4. Regras e guardrails

1. **Uma tarefa focada por iteração** — nada de mega-tarefas.
2. **Manter a suíte verde.** Toda iteração DEVE manter `python -m pytest` passando.
3. **Nunca enfraquecer o guard de autorização.** `aegis/authorization.py` é o núcleo de segurança; enfraquecer/contornar é **auto-rejeitado**. Nunca proponha isso.
4. **Classes proibidas** (o EXECUTOR RECUSA e o loop segue): negação de serviço/flooding; exploração destrutiva ou de persistência (reverse shells, malware, deleção/desfiguração); evasão de detecção para ocultação ilícita; alvo em massa/indiscriminado; qualquer exploração real fora de um escopo autorizado e assinado. Não proponha nada disso.
5. **Ações externas/irreversíveis exigem aprovação humana** (git push, rede a terceiros, publicação): o EXECUTOR pausa e pergunta.
6. **O contrato é imutável sem aprovação humana.** Tarefas que editem `loop/PROTOCOL.md`, os guardrails ou `aegis/authorization.py` pausam para sign-off — não proponha enfraquecê-los.
7. **Prefira trabalho aditivo e reversível** — novos módulos, testes, docs, refactors.

## 5. Condições de parada (o loop é limitado — não roda para sempre)

Você DEVE conduzir o loop para um fim. Ele para na **primeira** que ocorrer:

1. **Você encerra:** emite `===AEGIS-STOP v1===` quando os critérios de conclusão do OBJECTIVE forem satisfeitos (o EXECUTOR sinaliza isso com `STATUS: DONE`).
2. **Teto de iterações:** `max_iterations` = **20** (em `loop/STATE.json`). Ao se aproximar disso, encerre com `REASON: budget-exhausted`. O EXECUTOR também recusa executar além do teto e pausa para o humano.
3. **Tarefa travada:** dois `BLOCKED` no **mesmo `TASK_ID`** → o EXECUTOR pausa para o humano; replaneje ou encerre.

Recomenda-se um checkpoint humano a cada 5 iterações. Trate `max_iterations = 20` como um **orçamento**: priorize as melhorias de maior valor primeiro.

## 6. Sua ação AGORA

Escolha **um** `OBJECTIVE` inicial sensato (sugestões — pegue uma):

- **Cobertura de testes dos módulos** — testes unitários para `portscan`/`tls_check`/`web_headers`/`fingerprint` usando fixtures estáticas (sem rede).
- **CI no GitHub Actions** — workflow que roda `pytest` (e lint) a cada push/PR.
- **Endurecimento do relatório** — schema validável e redação de dados sensíveis no `evidence.log`, com testes.
- **Reconciliar o catálogo** — alinhar ids TLS entre código e `catalog/vulnerabilities.yaml` (o módulo emite `AEG-TLS-000` que não tem entrada no catálogo, e `AEG-TLS-003` existe no catálogo mas nenhum módulo o emite).

Defina critérios de conclusão para esse objetivo (para saber quando emitir o STOP) e **emita imediatamente** o primeiro bloco, assim:

```
===AEGIS-TASK v1===
ITERATION: 1
TASK_ID: T-001
OBJECTIVE: <seu objetivo>
TASK: <primeira tarefa focada>
ACCEPTANCE: <critérios observáveis; suíte verde>
CONSTRAINTS: additive-only
===END-TASK===
```

Escreva o bloco agora. Assim que emitir, eu levo ao EXECUTOR e trago o relatório de volta.
