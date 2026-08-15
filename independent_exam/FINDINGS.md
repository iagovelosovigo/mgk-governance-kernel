# Findings del Tester independiente

## Estado

El contrato y el examen están creados y congelados, pero todavía no se ha
evaluado ningún candidato MGK v0.1.0. Por diseño, la ausencia del adaptador o de
cualquier evidencia produce fallo; no existe un modo degradado de PASS.

## Hallazgos de diseño que el Builder debe resolver

1. La frontera planner no puede exponer `issue`, `sign`, `authorize`, `execute`,
   rotación de epoch ni material privado. Esto se comprueba además de atacar
   tokens fabricados con conocimiento completo del formato.
2. Verificar una capability no basta: los tests cuentan invocaciones de la
   operación protegida y exigen cero ante toda denegación.
3. El nonce debe consumirse atómicamente antes del efecto. Una excepción del
   efecto no restaura el nonce y no puede habilitar replay.
4. El epoch y el digest del recurso se revalidan en el commit. Rotación o
   sustitución durante `before_commit` anulan la ejecución.
5. Una corrupción del audit ledger bloquea ejecuciones posteriores y conserva
   evidencia; un ledger meramente append-only sin verificación de integridad no
   supera el examen.
6. `REQUIRE_XEITO` no es autorización provisional. Junto con
   `NON_TEN_XEITO`, debe producir exactamente cero invocaciones protegidas.
7. El importador de capabilities debe aceptar bytes hostiles como entrada no
   confiable y convertir cualquier error en token inválido/denegación auditable,
   no propagar una excepción que evite el registro.
8. La instalación limpia se ejecuta sin índice de red. Las dependencias de
   runtime deben ser estándar, vendorizadas o suministradas dentro del artefacto.
9. El umbral de mutation testing queda congelado en 90 %. Mutantes sobrevivientes
   en firmas, binding, replay, epoch, SAXP, audit o fail-closed impiden la release.

## Limitaciones deliberadas del examen

- El adaptador es una frontera de compatibilidad. No puede declarar PASS: sólo
  traduce la API del candidato al protocolo y las pruebas miden los efectos.
- Los PDF MUDA no se usan como evidencia científica ni como oráculo de PASS.
- No se emite veredicto de implementación desde este directorio; el veredicto lo
  calcula `tools/evaluate_acceptance.py` a partir de observaciones, artefactos y
  hashes verificables.

