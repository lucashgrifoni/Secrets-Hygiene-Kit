# Status - Secrets Hygiene Kit

Data: 2026-08-04
Versao: 0.2.0

## Status atual

`secguard` cobre o ciclo completo do escopo v0.1 da especificacao: ingestao de
relatorios reais de scanner, normalizacao canonica com redacao garantida,
catalogo de regras que liga deteccao a resposta, ciclo de vida de waivers com
expiry que falha fechado, gate de CI com codigos de saida estaveis, saidas em
JSON/SARIF/Markdown, e 13 playbooks de resposta com data de revisao verificada.

O projeto continua sem executar scanner e sem rotacionar, revogar ou mutar
estado de provider. Essas duas fronteiras sao invariantes de design, nao
limitacoes temporarias.

## Ultimo incremento (0.1.0 -> 0.2.0)

- Adapters de ingestao para gitleaks (JSON), trufflehog (JSON Lines e array) e
  detect-secrets (baseline), com inferencia de formato pela estrutura do payload.
- Merge entre scanners: o mesmo vazamento reportado por tres ferramentas vira um
  finding, na maior severidade atribuida, com `corroborated_by`.
- Catalogo de regras `secguard.rules/v1` (13 secret types) com override local via
  `.secguard/rules.yaml`; regra nao mapeada cai em fallback explicito.
- Escalonamento por verificacao: `Verified: true` do trufflehog eleva a critical.
- `secguard scan check` (gate), `report`, `waivers add`, `playbooks
  list|show|check`, `incident start`, `version`.
- SARIF 2.1.0 com regras por secret type canonico e waiver como `suppression`.
- 9 playbooks novos (13 no total) e `action.yml` composite + template GitLab.
- Docs: quickstart, incident-flow, adding-playbook; README e CHANGELOG reescritos.
- CI propria: testes e lint em Python 3.12/3.13, autoverificacao de playbooks e
  validacao dos recursos empacotados no wheel.

## Checks (executados em 2026-08-04)

| Verificacao | Comando | Resultado |
|---|---|---|
| Testes | `python -m pytest` | 237 passed |
| Lint | `python -m ruff check .` | All checks passed |
| Formatacao | `python -m ruff format --check .` | 34 files already formatted |
| Build | `python -m build` | sdist + wheel 0.2.0 |
| Package data no wheel | inspecao do `.whl` | 13 playbooks, 4 templates, `data/rules.yaml` |
| CLI a partir do wheel limpo | venv isolada | todos os comandos exercitados |
| Gate bloqueia | `scan check --fail-on high` (3 relatorios) | exit 1, `BLOCK: 2 finding(s)` |
| Gate passa | `scan check --fail-on none` | exit 0, `PASS` |
| Waiver suprime | waiver ativo + `--fail-on high` | `4 active, 1 waived` |
| Invariante de redacao | canario nos artefatos gerados | CLEAN (nenhum vazamento) |

## Cobertura de testes por area

- `test_redaction_invariant.py` - canario em JSON, SARIF, Markdown, PR comment e
  stdout, mais a prova de que as fixtures realmente contem o canario.
- `test_detectors.py` - parsing dos tres formatos, inferencia, merge, dedup,
  determinismo, erros acionaveis.
- `test_catalog.py` - resolucao, tolerancia a drift de nome, fallback, overrides.
- `test_matching.py` - semantica de glob de escopo de waiver.
- `test_reconcile.py` - thresholds, expiry fail-closed, waivers nao usados.
- `test_sarif.py` - envelope, agrupamento por secret type, suppressions.
- `test_playbooks.py` - forma obrigatoria, coerencia bidirecional com o catalogo,
  freshness, rejeicao de traversal de slug.
- `test_report_and_incident.py`, `test_cli.py`, `test_waivers.py`,
  `test_scaffold.py`, `test_findings.py`.

## Riscos e limites conhecidos

- **Mapeamentos de regra sao best effort.** IDs de regra de detector mudam entre
  releases. O catalogo mapeia apenas o que e defensavel; o resto cai em
  `mapping: fallback` e fica visivel na saida. Azure e Postgres tem cobertura
  parcial por falta de regra padrao confiavel em alguns detectores.
- **`Vetted` dos 9 playbooks novos e 2026-08-04**, data em que o conteudo foi
  escrito e revisado. Os 4 playbooks originais mantem 2026-05-18 porque nao
  foram re-verificados contra documentacao de vendor neste incremento.
- **Passos de playbook evitam caminhos de console** de proposito, para sobreviver
  a redesenho de UI. Isso os torna menos literais e mais duraveis.
- **Fingerprint do detect-secrets e derivado de localizacao**, nao do
  `hashed_secret`, o que custa estabilidade quando o codigo se move. Trade-off
  deliberado: SHA-1 de segredo de baixa entropia e recuperavel.
- **`corroborated_by` depende do merge por (secret_type, path, line).** Scanners
  que reportam linhas diferentes para o mesmo segredo nao serao unificados.
- **O projeto nao esta sob controle de versao** neste diretorio; nao ha commits,
  tags ou release publicada.

## Proximos passos sugeridos

1. Inicializar git, aplicar `commit-attribution-firewall` e publicar 0.2.0.
2. Comentario automatico em PR consumindo `--pr-comment` (roadmap v0.2 da spec).
3. Integracao com o Remediation Hub: criar task por finding com playbook anexo.
4. Ampliar o catalogo com fixtures reais redigidas de cada detector para reduzir
   a superficie de fallback.
5. Re-verificar os 4 playbooks originais contra documentacao de vendor e
   atualizar `Vetted`.

## Comando para retomar

```powershell
cd "C:\Users\Lucas Grifoni\Downloads\My Projects - AppSec & DevSecOps\Projects List - Andamento\9.Projeto - Secrets Hygiene Kit\secrets-hygiene-kit"
$env:PYTHONPATH = "src"
python -m pytest
python -m secguard scan check -i tests\fixtures\gitleaks-report.json -i tests\fixtures\trufflehog-report.jsonl -i tests\fixtures\detect-secrets-baseline.json --fail-on high --today 2026-08-04
```
