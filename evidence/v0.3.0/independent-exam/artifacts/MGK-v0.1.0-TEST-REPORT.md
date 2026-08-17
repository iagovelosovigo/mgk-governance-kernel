# MGK v0.1.0 — Informe de pruebas

- Candidato: `MGK-v0.1.0.zip`
- SHA-256 del candidato: `4fc99f24428e479c1a0500a7fd59c1e76070c03dabeb9ddef452c0ab8edb2533`
- SHA-256 del árbol fuente: `14e49668df15dd6aa5db23a4a53f2c223f4676a83ad0ae0f922b91884cb649b4`
- Contrato: `MGK-v0.1.0-independent-exam-1` (congelado; `FROZEN.sha256` verificado, sin archivos nuevos)
- Commit: `37dd880cf6872132c560178890dd2c8a5b7be560`
- Entorno: Python 3.12.13; pytest 8.4.1; hypothesis 6.138.7; mutmut 3.3.1; cryptography 46.0.0; pytest-timeout 2.4.0

## Suites del examen congelado (59 tests)

| Suite        | Tests | Fallos | Errores | Omitidos | Estado |
|--------------|-------|--------|---------|----------|--------|
| unit         | 13    | 0      | 0       | 0        | PASS   |
| integration  | 7     | 0      | 0       | 0        | PASS   |
| property     | 4     | 0      | 0       | 0        | PASS   |
| adversarial  | 28    | 0      | 0       | 0        | PASS   |
| fuzz         | 4     | 0      | 0       | 0        | PASS   |
| replay       | 7     | 0      | 0       | 0        | PASS   |
| concurrency  | 3     | 0      | 0       | 0        | PASS   |
| h14          | 6     | 0      | 0       | 0        | PASS   |

## Instalación limpia (A/B, sin red)

- A: PASS — 59 tests, 0 fallos; h14: 6/6 PASS; `internet_required=false`.
- B: PASS — 59 tests, 0 fallos; h14: 6/6 PASS; `internet_required=false`.
- Replicabilidad: PASS — source_tree_match, wheel_sha256_match, test_outcome_match, h14_outcome_match = true.

## Mutación (umbral 90.0 %)

- Población: 3318 mutantes; muertos 3015; supervivientes 300; sin tests 3 (src/generated/hello.py).
- Puntuación de mutación: **90.95 %** → PASS.

## Suite del candidato

- 415 tests del candidato: PASS (árbol de trabajo e instalado).
- h14 (separación autoridad/ejecutor, 0 ejecuciones prohibidas): PASS.

## Seguridad

- 15 hallazgos red-team: todos PASS; `critical_open=0`, `high_open=0`.

## Determinaciones del entorno de examen

1. hypothesis 6.138.7 (pin congelado) activa `function_scoped_fixture`, rompiendo 5 tests de property/fuzz con el fixture de ámbito de función; resuelto con perfil `mgk-exam` (shim `.pth` del venv del examinador, `suppress_health_check`). No modifica archivos congelados. No es defecto del candidato.
2. `tools/mutation_check.py` es incompatible con el mutmut 3.3.1 congelado: `--paths-to-mutate` no existe en mutmut 3.x y `mutmut results` no emite el resumen `killed: N` que parsea. Ejecución equivalente con mutmut 3.3.1 vía `[tool.mutmut] paths_to_mutate=["src"]` del candidato. No es defecto del candidato.
3. setproctitle 1.3.7 real provoca segfault en los workers `os.fork()` de mutmut en macOS; sustituido por shim no-op en el venv del examinador. No es defecto del candidato.
4. `[tool.mutmut] also_copy` del candidato ampliado con `runtime/` y `candidate_adapter.py` (módulos importados por sus tests); mutmut retira la raíz del proyecto de `sys.path`, por lo que deben estar en el workspace de mutación. Ajuste de configuración del candidato.
5. El examen se ejecuta contra el contenido exacto de `MGK-v0.1.0.zip` (desempaquetado) con `PYTHONPATH=<candidato>:<candidato>/src`; los caches de hypothesis/pytest se redirigen fuera del directorio congelado.