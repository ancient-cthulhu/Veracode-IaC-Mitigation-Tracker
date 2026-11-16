# Seguimiento de mitigaciones de Veracode IaC

[English](../../README.md) | Español

Un tracker autónomo de GitHub Actions para los hallazgos de Veracode Container, IaC y Secrets. Sigue los hallazgos a lo largo del tiempo y registra mitigaciones aprobadas; los clientes no tienen que instalar nada.

## Configuración

1. **Use this template > Create a new repository** (privado).
2. Settings > Secrets and variables > Actions:
   - secretos `VERACODE_API_ID` y `VERACODE_API_KEY`
   - variable `MITIGATION_APPROVERS`: logins de GitHub que pueden aprobar, por ejemplo `alice bob`
   - variable opcional `VERACODE_TRACK_ARGS` con filtros de escaneo, por ejemplo `--asset my-org/*`
3. Actions > **Veracode findings tracker** > **Run workflow** (después se ejecuta cada día a las 05:23 UTC).

## Cómo funciona

| Cuándo | Qué pasa |
| --- | --- |
| Día 1 | La ejecución diaria encuentra `AVD-AWS-0086` en `acme/payments-infra`. Aparece como **New** en `FINDINGS.md` con un enlace **Mitigate** |
| Día 2 | Sigue en el último escaneo: **Open**. Days Open va sumando |
| Solicitud | Un desarrollador pulsa **Mitigate**. Se abre una incidencia ya rellenada; elige el tipo, escribe el motivo y una fecha de caducidad |
| Aprobación | Un aprobador añade la etiqueta `approved`. El bot registra `M-0001` en `mitigations.yml`, marca el hallazgo como **Mitigated**, comenta y cierra la incidencia |
| Corrección | Otro hallazgo se corrige y su asset se vuelve a escanear. La siguiente ejecución lo pasa a `tracking/fixed.csv` con Fixed On y Days Open |
| Regresión | Un hallazgo corregido vuelve: **Reopened**, con su First Seen original |
| Caducidad | 30 días antes de `expires` la mitigación aparece como **Expiring**; después, **Expired** y el hallazgo vuelve a contar como abierto |

Cada cambio es un commit (`Daily findings: +2 new, -1 fixed`), así que el historial de git es la auditoría.

## Archivos

| Archivo | Contenido |
| --- | --- |
| `FINDINGS.md` | Panel: totales, nuevos, mitigaciones que caducan, abiertos, corregidos en los últimos 30 días. Enlaces a Veracode y Mitigate |
| `tracking/findings.csv` | Hallazgos abiertos: estado, severidad, ubicación, First Seen, Days Open, mitigación |
| `tracking/fixed.csv` | Hallazgos corregidos, con Fixed On y Days Open |
| `mitigations.yml` | Mitigaciones aprobadas. Consulta [MITIGATIONS.md](MITIGATIONS.md) |
| `tracker/` | Seguimiento, cliente de API de Veracode y utilidades de salida |

`FINDINGS.md` y `tracking/` se crean en la primera ejecución. Cada ejecución adjunta además un informe completo
en Excel (artefacto `veracode-findings`, 30 días, sin líneas de código).

## Estados

| Status | Significado |
| --- | --- |
| New | Visto por primera vez en esta ejecución. Open desde el día siguiente |
| Open | Está en el último escaneo de su asset |
| Reopened | Estaba corregido y ha vuelto |
| Asset Missing | El asset ya no está en Veracode. A los 30 días pasa a `fixed.csv` como `asset-removed` |
| Fixed | Ya no está en un escaneo más reciente de su asset. Pasa a `fixed.csv` |

Un hallazgo solo se marca como corregido cuando su asset se ha vuelto a escanear. Si falla alguna petición, la
ejecución no cambia nada y abre una incidencia con la etiqueta `tracker-failure` (se cierra con la siguiente
ejecución correcta). Si la protección de rama rechaza el push, la actualización va a la rama `tracking`.

## Flags

| Flag | Efecto |
| --- | --- |
| `--track DIR` | Actualiza `DIR/findings.csv`, `DIR/fixed.csv` y el panel |
| `--offline` | Con `--track`: actualiza Days Open, las mitigaciones y el panel sin llamar a Veracode |
| `--mitigations ARCHIVO` | El archivo de reglas, `mitigations.yml` |
| `--check-mitigations ARCHIVO` | Valida y lista las reglas, y termina. `--against BASE` muestra los cambios respecto a otro archivo |
| `--dashboard ARCHIVO` | Ruta del panel (por defecto `FINDINGS.md` junto a `DIR`) |
| `--repo-url URL` | `https://github.com/<org>/<repo>` para los enlaces Mitigate (se detecta en GitHub Actions) |
| `--migrate CSV_ANTIGUO` | Importa las mitigaciones de un `veracode-findings.csv` (automático si está junto a `DIR`) |
| `-o ARCHIVO` | Con `--track`: escribe además cada hallazgo actual con todas las columnas (`.xlsx`, `.csv`, `.json`, `.jsonl`) |
| `--asset`, `--exclude-asset`, `--scan-type`, `--asset-type`, `--scanned-by`, `--policy`, `--since`, `--until` | Filtros de escaneo: qué assets se siguen. Mismos valores que en el extract |
| `--rps`, `--max-workers`, `--max-attempts`, `--timeout`, `--ca-cert`, `--base-url`, `--link-base` | Conexión. `--base-url` es obligatorio en FedRAMP |

Los filtros de hallazgo (`--severity`, `--type`, ...) se rechazan: un hallazgo filtrado parecería corregido.

En local: `python tracker/veracode_iac_tracker.py --track tracking --mitigations mitigations.yml`

Códigos de salida: 0 completado, 1 falló una petición o un archivo estaba bloqueado (no cambia nada), 2 argumentos
incorrectos o `mitigations.yml` no válido, 3 el aprobador no está en `MITIGATION_APPROVERS`.

## Requisitos

El tracker es autónomo y no depende de Veracode-IaC-Extract. El cliente de API y las utilidades de salida están en `tracker/`.
- Un repositorio de GitHub con Actions e Issues activados
- Una cuenta de servicio de la API de Veracode con rol Reviewer que pueda ver los escaneos de Container e IaC
- Para ejecutarlo en local: Python 3.9 o posterior, `pip install -r requirements.txt`, y credenciales en
  `~/.veracode/credentials` o en las variables de entorno `VERACODE_API_ID` y `VERACODE_API_KEY`
  (también se aceptan `VERACODE_API_KEY_ID` / `VERACODE_API_KEY_SECRET`)

## Documentación relacionada

- [MITIGATIONS.md](MITIGATIONS.md): solicitar, aprobar, editar y revocar mitigaciones; campos de `mitigations.yml`
- [Veracode-IaC-Extract](https://github.com/ancient-cthulhu/Veracode-IaC-Extract): la herramienta de exportación, sus filtros, columnas y API de librería
