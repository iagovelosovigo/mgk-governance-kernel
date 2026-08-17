# MGK v0.1.0 — Informe red-team

- Candidato: `MGK-v0.1.0.zip`
- SHA-256 del candidato: `4fc99f24428e479c1a0500a7fd59c1e76070c03dabeb9ddef452c0ab8edb2533`
- Fuente: `evidence/v0.3.0/redteam/redteam.json`
- Resultado global: **PASS** — `critical_open=0`, `high_open=0`

## Ataques

| ID             | Resultado | Descripción                              |
|----------------|-----------|------------------------------------------|
| R1-csrf        | PASS      | propuesta cross-origin rechazada         |
| R1-sameorigin  | PASS      | propuesta same-origin aceptada solo para gating |
| R2-symlink     | PASS      | escape por symlink bloqueado (sin ALLOW) |
| R3-append-gate | PASS      | append está gateado (sensible)           |
| R4-approve-missing | PASS  | aprobar propuesta inexistente falla en modo seguro |
| R5-double-approve | PASS   | segunda aprobación no duplica ejecución  |
| R6-nonce-replay | PASS     | capabilities de un solo uso, sin reuso   |
| R7-flight-tamper | PASS    | manipulación del flight recorder detectada |
| R8-audit-tamper | PASS     | manipulación del audit detectada por doctor |
| R9-key-perms   | PASS      | clave privada en modo 0600               |
| R10-oversize   | PASS      | payload sobredimensionado falla cerrado  |
| R11-unknown-action | PASS  | acción desconocida denegada              |
| R12-deny-mode  | PASS      | modo `deny_all` verificado               |
| R13-absolute   | PASS      | ruta absoluta denegada                   |
| R14-malformed-body | PASS  | parámetros no-mapping manejan fail-closed |

## Resumen

- Total de hallazgos: 15.
- Hallazgos abiertos: críticos 0, altos 0.
- Verificación post-ataque (`mgk doctor` 7/7 y suite de pruebas): PASS.