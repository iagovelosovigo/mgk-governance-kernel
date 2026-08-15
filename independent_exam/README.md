# MGK v0.1.0 — examen independiente congelado

Este directorio contiene el examen independiente para decidir si una
implementación candidata satisface la misión MGK v0.1.0. El examen no contiene
código del candidato y no confía en afirmaciones del builder.

## Interfaz del candidato

La implementación se conecta mediante un módulo adaptador indicado por
`MGK_CANDIDATE_ADAPTER` (por defecto, `candidate_adapter`). El módulo debe
exportar:

```python
def create_harness(root: pathlib.Path, clock: FrozenClock) -> Harness: ...
```

El contrato normativo completo está en `api_contract.py`. La frontera de datos
es deliberadamente simple: requests, decisiones y resultados son diccionarios
JSON; las capabilities son objetos opacos, pero el adaptador debe permitir
exportarlas, importarlas, inspeccionar sus claims públicos y ensamblar tokens
adversariales sin acceso a la clave privada.

El adaptador forma parte del pegamento de examen, no de la autoridad. Los tests
comprueban los efectos observables: una denegación sólo cuenta como segura si la
operación protegida no fue llamada.

## Ejecución

```bash
python -m pytest -q
python tools/check_frozen.py
python tools/evaluate_acceptance.py \
  --observations evidence/observations.json \
  --out evidence/functional-verdict.json
```

Para que `FUNCTIONAL = TRUE`, deben ejecutarse también dos instalaciones limpias
e independientes y la comparación de reproducibilidad:

```bash
python tools/clean_install.py --source /ruta/MGK-v0.1.0.zip --label A --out evidence/clean-A.json
python tools/clean_install.py --source /ruta/MGK-v0.1.0.zip --label B --out evidence/clean-B.json
python tools/reproducibility.py evidence/clean-A.json evidence/clean-B.json --out evidence/reproducibility.json
```

`FUNCTIONAL-ACCEPTANCE.yaml` está escrito como JSON válido (y por tanto YAML
válido) para poder verificarse con la biblioteca estándar. `FROZEN.sha256`
ancla todos los contratos, tests y herramientas del examen. Un cambio posterior
en un archivo protegido invalida el examen hasta que una autoridad humana
apruebe una nueva versión del contrato.

## Principios examinados

- `I != A`: el planner sólo propone; no posee material de firma ni decide PASS.
- H14: un planner comprometido no consigue ninguna ejecución prohibida.
- SAXP: `REQUIRE_XEITO` y `NON_TEN_XEITO` ejecutan exactamente cero operaciones.
- Fail-closed: error, ambigüedad, corrupción o evidencia incompleta anulan la
  autoridad de ejecución preservando evidencia.
- Binding total: acción, recurso, payload, scope, epoch, tiempos y nonce están
  cubiertos por la firma y se verifican en el momento de uso.
- Uso único: un nonce se consume atómicamente; fallo y concurrencia no abren una
  ventana de replay.
- Anti-TOCTOU: el recurso autorizado no puede sustituirse entre verificación y
  commit.

