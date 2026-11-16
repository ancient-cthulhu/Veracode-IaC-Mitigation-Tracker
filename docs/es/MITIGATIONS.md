# Mitigaciones

[English](../MITIGATIONS.md) | Español

Veracode no tiene mitigaciones para los hallazgos de Container, IaC y Secrets, así que este tracker las guarda en
[`mitigations.yml`](../../mitigations.yml). Un hallazgo mitigado aparece como **Mitigated** en `FINDINGS.md`, las páginas
de equipo y de asset, `tracking/findings.csv` y el informe de Excel. **No** cambia nada en Veracode (ver
[Límites](#límites)).

## Configuración inicial (administrador del repositorio)

| Qué | Dónde | Notas |
| --- | --- | --- |
| Aprobadores | **Settings → Secrets and variables → Actions → Variables** → `MITIGATION_APPROVERS` | Usuarios de GitHub separados por espacios o comas: `alice bob`. Debe ser una **variable**, no un secreto. Vacía = nadie puede aprobar |
| Acceso de aprobadores | **Settings → Collaborators and teams** | Necesitan al menos **Triage**, o no pueden añadir etiquetas |
| Etiquetas | Las crea la primera ejecución del tracker | `mitigation-request` y `approved`. No las renombres |
| Protección de rama | **Settings → Branches** | El bot sube las aprobaciones a la rama principal. Si la protección bloquea GitHub Actions, las aprobaciones fallan |

## Solicitar una mitigación (cualquiera)

1. Abre `FINDINGS.md`, la página de tu equipo o la del asset en `findings/`.
2. Pulsa **Mitigate** en el hallazgo. Se abre una incidencia ya rellenada. No cambies **Finding Key**.
3. Rellena:
   - **Type**: ver [Tipos](#tipos).
   - **Reason**: por qué no hace falta corregirlo. Sé concreto; el aprobador decide con esto.
   - **Expires**: `YYYY-MM-DD`, en el futuro. Obligatorio para `accept-risk`, opcional en los demás.
   - **Asset / File**: déjalos como están para mitigar solo este hallazgo. Ver [Alcance](#alcance) para cubrir más.
4. Envíala. En un minuto el bot comenta los detalles del hallazgo: severidad, archivo, recurso, escaneo, enlace a
   Veracode, descripción y cuántos otros assets tienen el mismo hallazgo.

¿No hay enlace Mitigate? El hallazgo ya está **Mitigated**, o el informe se generó fuera de GitHub Actions.

## Aprobar o rechazar (aprobadores)

- **Aprobar:** añade la etiqueta **`approved`** y deja **`mitigation-request`** en la incidencia (ver la primera fila de
  [Problemas frecuentes](#problemas-frecuentes)). En un minuto el bot comenta `Approved as M-0001, applied to N finding(s)`,
  sube `mitigations.yml` y los informes actualizados, y cierra la incidencia.
- **Rechazar:** cierra la incidencia sin la etiqueta. No se registra nada.

## Tipos

| Tipo | Cuándo | Expires |
| --- | --- | --- |
| `false-positive` | El hallazgo no es real | Opcional |
| `by-design` | Es intencionado y está aprobado | Opcional |
| `network-environment` | Un control de red lo bloquea: WAF, security group, red privada | Opcional |
| `os-environment` | El sistema o el runtime lo bloquea: host bastionado, sistema de archivos de solo lectura, sin shell | Opcional |
| `accept-risk` | El negocio acepta el riesgo durante un tiempo | **Obligatorio** |

## Alcance

| Asset | File | Finding ID | Mitiga |
| --- | --- | --- | --- |
| Como viene | Vacío | Cualquiera | Solo este hallazgo |
| Comodín: `acme/payments-*` o `*` | Cualquiera | **Obligatorio** | Este Finding ID en cada asset que coincida |
| Cualquiera | Patrón: `modules/status/*` | **Obligatorio** | Este Finding ID en los archivos que coincidan |

`*` es cualquier texto, `?` un carácter, sin distinguir mayúsculas. El comentario de detalles avisa cuando el mismo
Finding ID está abierto en otros assets: ahí un comodín ahorra solicitudes.

## Después de aprobar

| Mitigation Status | Significado |
| --- | --- |
| `Mitigated` | Una regla coincide. El hallazgo deja de contar como abierto y no tiene enlace Mitigate |
| `Expiring` | Caduca en 30 días o menos. Aparece en **Needs action** |
| `Expired` | Pasada la fecha `expires`. Vuelve a contar como abierto, aparece en **Needs action** con un enlace Mitigate para renovarla |

## Problemas frecuentes

| Qué ves | Por qué | Solución |
| --- | --- | --- |
| Añadiste `approved` y **no pasó nada** (la ejecución sale *skipped*) | La incidencia perdió la etiqueta `mitigation-request`. El selector de etiquetas de GitHub puede desmarcarla al marcar `approved` | Vuelve a añadir `mitigation-request`, quita `approved` y añádela otra vez |
| Se quita la etiqueta, comentario "is not an approver" | Tu usuario no está en `MITIGATION_APPROVERS`, o la variable está vacía o se creó como secreto | Pide a un administrador que te añada a la variable y vuelve a etiquetar |
| Se quita la etiqueta, comentario "This mitigation was not recorded" con una lista | El formulario no es válido: falta el motivo, tipo incorrecto, fecha incorrecta o pasada, comodín o File sin Finding ID, Finding Key vacío o mal formado | Edita la incidencia y vuelve a etiquetar |
| Se quita la etiqueta, "edited after the label was added" | Alguien editó la incidencia después de añadir `approved` | Revisa el cambio y vuelve a etiquetar |
| Se quita la etiqueta, "the issue is closed" | La incidencia estaba cerrada | Reábrela y vuelve a etiquetar |
| No hay comentario de detalles | La incidencia no se abrió desde el enlace Mitigate o el formulario, o el hallazgo ya no se sigue | Abre una solicitud nueva desde el enlace Mitigate. El comentario avisa si el hallazgo ya está corregido |
| La aprobación **falla** y la incidencia sigue abierta | El bot no pudo subir el cambio (protección de rama) | Permite que GitHub Actions suba a la rama principal y vuelve a etiquetar |
| Editaste la incidencia después de aprobar y no cambió nada | Una regla se registra una vez; volver a etiquetar solo dice `Already recorded` | Cambia la regla en un pull request ([abajo](#cambiar-renovar-o-revocar)) |
| Un hallazgo mitigado vuelve a salir como **New** | Su Finding Key cambió: archivo o recurso renombrado, o cambió el valor de un secreto | Mitígalo de nuevo, o usa una regla por Finding ID con alcance de asset o archivo |
| Sigue el estado antiguo después de aprobar | La página se cargó antes del commit del bot | Recarga. Busca el commit `Approve mitigation M-...` |

## Cambiar, renovar o revocar

Edita `mitigations.yml` en un pull request:

- **Renovar:** cambia `expires`.
- **Ampliar o reducir:** cambia `asset` o `file` (con `finding` igual al Finding ID).
- **Revocar:** borra la entrada. Los hallazgos vuelven a contar como abiertos en la siguiente ejecución.

El pull request recibe un comentario con las reglas añadidas, cambiadas o eliminadas y cuántos hallazgos abiertos cubre
cada una. La comprobación falla si el archivo no es válido; hazla obligatoria.

```yaml
- id: M-0001
  finding: AVD-AWS-0086          # Finding ID, CVE o Finding Key (mk-...)
  asset: acme/payments-*         # opcional
  file: modules/status/*         # opcional
  type: accept-risk
  reason: Public status page served through CloudFront
  approved_by: lead-dev
  approved_on: 2026-11-15
  expires: 2027-11-09            # obligatorio para accept-risk
  ref: https://github.com/acme/veracode-findings/issues/12
```

| Campo | Obligatorio | Notas |
| --- | --- | --- |
| `id` | Sí | Formato `M-0001`, único. El bot usa el siguiente número libre |
| `finding` | Sí | Finding ID, CVE o Finding Key; admite comodines |
| `asset`, `file` | No | Reducen el alcance; admiten comodines |
| `type`, `reason`, `approved_by` | Sí | |
| `expires` | Para `accept-risk` | `YYYY-MM-DD`; el hallazgo vuelve a estar abierto desde el día siguiente |
| `approved_on`, `requested_by`, `ref`, `notes` | No | Los pone el bot; `notes` guarda el número de ticket |
| `allow_broad` | No | `true` para permitir una regla que coincide con todos los hallazgos (`finding: "*"` sin otro alcance) |

Si coinciden varias reglas, gana la primera sin caducar del archivo. Más ejemplos:
[examples/mitigations.example.yml](../../examples/mitigations.example.yml).

En local:

```bash
python tracker/veracode_iac_tracker.py --check-mitigations mitigations.yml                        # validar
python tracker/veracode_iac_tracker.py --track tracking --offline --mitigations mitigations.yml   # aplicar, sin llamar a Veracode
```

## Límites

- Las mitigaciones se aplican solo a este tracker y sus informes: no a la Veracode Platform, las políticas ni las
  puertas de los pipelines.
- Una incidencia aprobada = una regla. Para cubrir muchos hallazgos a la vez, usa un [alcance](#alcance) con comodín.

## Seguridad

- Solo los usuarios de `MITIGATION_APPROVERS` pueden aprobar; cambiar la variable requiere acceso de administrador.
- Protege `mitigations.yml`, `teams.yml`, `.github/` y `tracker/` con [CODEOWNERS](../../.github/CODEOWNERS) y
  protección de rama.
- El texto de la incidencia nunca llega a una shell, y todo lo que se muestra en comentarios e informes se escapa.
- La comprobación del pull request usa el tracker de la rama base, así que un pull request no puede cambiar su propia
  comprobación.

## veracode-findings.csv existente

Si hay un `veracode-findings.csv` con mitigaciones junto a la carpeta `tracking`, la primera ejecución copia sus
mitigaciones a `mitigations.yml` (`ref: migrated`) y conserva el First Seen de cada hallazgo. Después borra el CSV.
