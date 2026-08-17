# Fase 12 — Examen independiente congelado

- Contrato: `MGK-v0.1.0-independent-exam-1` (`independent_exam/`, verificado con `check_frozen.py`).
- Candidato: `MGK-v0.1.0.zip` (121 archivos, SHA-256 `4fc99f24...edb2533`) — contenido exacto del árbol v0.3.0.
- Commit del candidato: `37dd880cf6872132c560178890dd2c8a5b7be560`.

## Resultados

| Observación        | Estado   | Detalle                                                      |
|--------------------|----------|--------------------------------------------------------------|
| Suites congeladas  | PASS     | unit 13, integration 7, property 4, adversarial 28, fuzz 4, replay 7, concurrency 3, h14 6 (59 tests, 0 fallos) |
| Instalación limpia | A/B PASS | 59 tests + 6 h14 en cada venv nuevo; sin red (`internet_required=false`) |
| Replicabilidad     | PASS     | source_tree, wheel_sha256 (c7793c6c en ambos), test_outcome, h14_outcome |
| Mutación           | PASS     | 3318 mutantes, 3015 muertos, 300 supervivientes, 90.95 % (umbral 90.0) |
| Seguridad red-team | PASS     | 15 hallazgos, `critical_open=0`, `high_open=0`                |
| Artefactos         | PASS     | 10/10 requeridos presentes y con hash verificado             |
| **VEREDICTO**      | **FUNCTIONAL = TRUE** | sin condiciones incumplidas                          |

## Determinaciones del entorno de examen

1. hypothesis 6.138.7 (pin congelado) activa `function_scoped_fixture` → perfil `mgk-exam` vía shim `.pth` del venv del examinador. No es defecto del candidato.
2. `mutation_check.py` usa flags/formato de mutmut 2.x incompatibles con el mutmut 3.3.1 congelado → ejecución equivalente con 3.3.1 vía `paths_to_mutate=["src"]` del candidato. No es defecto del candidato.
3. setproctitle 1.3.7 real segfault en workers `fork()` de mutmut en macOS → shim no-op. No es defecto del candidato.
4. `[tool.mutmut] also_copy` ampliado con `runtime/` + `candidate_adapter.py` (ajuste de configuración del candidato).
5. Caches de hypothesis/pytest redirigidos fuera del directorio congelado; examen ejecutado contra el contenido exacto del zip.

## Artefactos

`evidence/v0.3.0/independent-exam/artifacts/` — `MGK-v0.1.0.zip(.sha256)`, `-SBOM.json`, `-MANIFEST.json`, `-FUNCTIONAL-VERDICT.json/.md`, `-TEST-REPORT.md`, `-RED-TEAM-REPORT.md`, `-FAILURE-LEDGER.jsonl`, `-EVIDENCE.tar.gz`, `observations.json`.

## Secundario

- `dist/` reconstruido con `SOURCE_DATE_EPOCH=1700000000` tras ampliar `also_copy`; el wheel `c7793c6c` es byte-idéntico (contenido desempaquetado) al de la fase 11 y coincide con el wheel de instalación limpia A/B.