# MGK Autopilot Bootstrap RC.2 - PR Gated

Bootstrap F00 endurecido para separar propuesta, verificación, autorización y ejecución.
Codex sólo genera un parche. Un TCB protegido valida su alcance, los gates inspeccionan
`hello.py` mediante AST sin ejecutar código candidato, y el workflow sólo puede publicar una
rama y un Pull Request. No existe ninguna operación automática de aprobación o merge.

## Configuración obligatoria en GitHub

1. Crea un repositorio cuya rama principal sea `main` y copia este contenido.
2. Añade `OPENAI_API_KEY` como secreto del repositorio.
3. Crea la variable de repositorio `MGK_ROOT_MANIFEST_SHA256` con este valor:

   ```text
   6bc16cd3076bf2f5b0a4cd595680de244cdfbccbf3c282b527a411b1f5eb09c8
   ```

4. En **Settings > Actions > General > Workflow permissions**, permite a GitHub Actions crear
   Pull Requests.
5. Crea el environment `mgk-promotion` y exige al menos un revisor humano.
6. Protege `main` mediante ruleset o branch protection:
   - exige Pull Request y al menos una aprobación;
   - descarta aprobaciones obsoletas y exige aprobación del push más reciente;
   - exige el status check `mgk/deterministic-gates` y rama actualizada;
   - bloquea force-push, borrado de rama y bypass de las reglas;
   - no habilites auto-merge para `mgk-autopilot/**`.
7. Ejecuta `MGK Bootstrap Core RC.2 - PR Gated` desde `main` en **Actions**.

## Garantías de esta variante

- Las acciones de terceros están fijadas por commit SHA.
- El manifiesto externo cubre workflow, contratos, TCB y gates protegidos.
- La allowlist se deriva de `contracts/PHASES.yaml`; renames, symlinks, submódulos y modos
  ejecutables no permiten escapar de `src/generated/**`.
- `STATE_INTEGRITY` exige un hash válido desde el estado génesis y falla si falta.
- Los gates no importan ni ejecutan `hello.py`; validan su forma y retorno mediante AST.
- La transición `F00 -> DONE` se prueba sobre el commit exacto que será cabeza del PR.
- El status `mgk/deterministic-gates`, el PR y la attestation incluyen el SHA exacto del commit.
- Los artefactos temporales no se incorporan al commit candidato.

## Resultado esperado

El workflow crea una rama `mgk-autopilot/f00-*`, publica una attestation, fija un status sobre
su commit exacto y abre un Pull Request. El workflow termina sin aprobar ni fusionar. La
autorización final permanece en el revisor humano y en las reglas protegidas de `main`.

## Alcance

Éste es el Bootstrap Root F00 corregido. No equivale todavía al veredicto final
`MGK v0.1.0 - FUNCTIONAL = TRUE`, que requiere el Governance Kernel completo, H14 y el resto
de fases del contrato global.
