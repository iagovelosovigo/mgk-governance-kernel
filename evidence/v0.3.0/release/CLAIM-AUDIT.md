# Fase 13 — Auditoría de reclamaciones (CLAIM AUDIT)

Candidato: MGK v0.3.0 publishable-candidate.
Commit auditado: `c444762` (evidencia de la campaña completa, fases 4–12).
Método: recomputación independiente de cada reclamación desde su evidencia cruda; verificación de hashes y de consistencia cruzada.

| ID  | Reclamación                                    | Evidencia                                                          | Resultado  |
|-----|------------------------------------------------|--------------------------------------------------------------------|------------|
| C1  | Población/puntuación de mutación recomputada desde resultados crudos | `population-experiment.json` (3315/3015/300/0.909502); recompute examen `mutation-meta/` (3015/300/3, score 90.95 %) | **VERIFICADO** |
| C2  | Consistencia de disposiciones phase 4          | `sensitive-survivor-classification.json` (104 sensibles; NOT_TARGET 71, EQUIVALENT_PROVEN 31, AVAILABILITY_ONLY 1, TEST_GAP_ONLY 1; 0 sin disposición; sha256 verificado) | **VERIFICADO** |
| C3  | Red-team adversarial todo-PASS                 | `redteam.json` (15 hallazgos, all_pass=true; critical_open=0, high_open=0; doctor post-ataque PASS) | **VERIFICADO** |
| C4  | Instalación limpia A/B reproducible            | `clean-A.json`/`clean-B.json` (PASS, 59+6, wheel `c7793c6c` idéntico); `reproducibility.json` PASS (source_tree, wheel_sha256, test_outcome, h14_outcome) | **VERIFICADO** |
| C5  | Endurecimiento de permisos                     | `delivery-package-and-smoke.json` live_perms 0700/0700/0600; red-team R9-key-perms PASS | **VERIFICADO** |
| C6  | Compuerta de adecuación de mutación            | `security-adequacy-gate.json` (gate_result PASS, GLOBAL_MUTATION_SCORE 0.909502, UNRESOLVED_HIGH 0, UNRESOLVED_CRITICAL 0, INDETERMINATE 0, FINAL_BYPASSES 0) | **VERIFICADO** |
| C7  | Raíz de confianza SIN CAMBIOS + escaneo de secretos CLEAN | `phase9-secrets-root-of-trust.json` (protected_tree PASS, 27/27 rutas, ancla `4c309aad…`, secret_scan CLEAN, 112 archivos, 0 en todas las categorías) | **VERIFICADO** |
| C8  | Examen independiente congelado FUNCTIONAL = TRUE | `MGK-v0.1.0-FUNCTIONAL-VERDICT.json` (functional=true, 0 fallos); `observations.json` (8/8 suites PASS, mutación 90.95, A/B PASS, repro PASS) | **VERIFICADO** |
| C9  | Paquete de entrega construye/instala/smoke     | `delivery-package-and-smoke.json` (wheel `c7793c6c`, sdist `f0a3297d`, smoke PASS, suite instalada 415/415) | **VERIFICADO** |

## Verificaciones cruzadas (integridad de evidencia)

- source_sha256 idéntico en clean-A, clean-B y observations: `4fc99f24…` (el contenido examinado es exactamente el candidato). ✔
- Wheel de instalación limpia == wheel de dist: `c7793c6cf238331a548acd6138b5edaa4c48f7ff8af9a9b1d018e388d37ba7d2`. ✔
- Recompute de mutación (examen) == experimento de población: 3015 muertos / 300 supervivientes. ✔
- `sensitive-survivor-classification.json` verifica contra su `.sha256`. ✔
- Clasificación de mutación interna: KILLED 3015 + SURVIVED_KILLABLE 209 + EQUIVALENT_PROVEN 91 = 3315. ✔
- Disposiciones phase 4: 71 + 31 + 1 + 1 = 104 = security_sensitive_survivors. ✔

## Conclusiones

- **9/9 reclamaciones VERIFICADAS**, 0 fallos.
- No hay reclamaciones no soportadas por evidencia cruda reproducible.
- Toda la evidencia referenciada vive en `evidence/v0.3.0/` y está comprometida en `c444762`.