# MGK v0.3.0 — Notas de versión (candidato)

## Resumen

MGK v0.3.0 reconcilia la frontera de arquitectura MUDA/MGK, endurece los límites de autoridad (separación autoridad/ejecutor, h14) y acredita adecuación de mutación sobre la población completa, con un examen independiente congelado que emite **FUNCTIONAL = TRUE**. La entrega queda **técnicamente lista para revisión humana de liberación**; ninguna operación de liberación (merge/tag/release/publish) ha sido ejecutada.

## Cambios principales (desde v0.2.0)

- **Arquitectura**: documento de frontera MUDA/MGK y contrato de alcance (fase 2–3); reconcilación de la separación autoridad/ejecutor.
- **Endurecimiento de autoridad**: máquina de estados de DENY humano durable (h14), autorización de propuesta separada de la ejecución; anti-TOCTOU, unicidad de capabilities (nonce atómico).
- **Versión**: 0.2.0 → 0.3.0 (`src/mgk/__init__.py`).
- **Pruebas**: 415 tests (2 tests discriminantes nuevos de la fase 4–6), todos PASS.

## Acreditaciones (fases 7–13)

| Acreditación | Resultado |
|---|---|
| Adecuación de mutación (población completa src/mgk, 3315) | 90.95 % (umbral 90 %) — PASS |
| Supervivientes sensibles disposicionados | 104/104, 0 sin disposición |
| Compuerta de seguridad | PASS — 0 altos, 0 críticos, 0 indeterminados, 0 bypasses |
| Escaneo de secretos | CLEAN (112 archivos) |
| Raíz de confianza | SIN CAMBIOS (ancla `4c309aad…`) |
| Instalación limpia A/B | PASS (sin red) |
| Replicabilidad | PASS |
| Examen independiente congelado | FUNCTIONAL = TRUE (8/8 suites, mutación 90.95 %) |
| Red-team | 15 hallazgos, 0 críticos, 0 altos |
| Auditoría de reclamaciones | 9/9 VERIFICADAS |

## Artefactos

- Candidato examinado: `MGK-v0.1.0.zip` sha256 `4fc99f24…`
- Wheel: `muda_governance_kernel-0.3.0-py3-none-any.whl` sha256 `c7793c6c…` (byte-idéntico al wheel de instalación limpia)
- Sdist: `muda_governance_kernel-0.3.0.tar.gz` sha256 `f0a3297d…`

## Estado de liberación

- **Técnicamente listo para revisión humana.**
- La liberación real (merge a main, tag, release, publish) está **reservada a un humano**. La compuerta humana permanece CERRADA y el pipeline automatizado no la ha cruzado.