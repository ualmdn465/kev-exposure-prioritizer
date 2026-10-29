# ROADMAP — Priorizador KEV + exposición

> Objetivo final: una herramienta que puedes llevar a una red **autorizada** (tu laboratorio, una empresa que te lo permite por escrito). Construye el inventario a partir de lo que encuentra (tráfico, escaneo, datos de la empresa) y te dice qué corregir primero, en qué plazo y por qué.
>
> Principio de diseño: **el núcleo (tier + score) no cambia**. Escalar consiste en añadir colectores que generan `assets.json` y `findings.json` con el esquema de `DESIGN.md`.

## v0 — Núcleo y evaluación (3 semanas)

### Semana 1 (27 oct – 2 nov): el núcleo, sin red
1. Cerrar el diseño: contrastar la matriz con la *Table 1* de BOD 26-04, crear `Fundamentos/Python/kev-exposure-prioritizer/` y subir `DESIGN.md`.
2. Datos de ejemplo: los 5 activos de la sección 6 en `assets.json`, `findings.json` y `cve_info.json`, más `weights.toml`.
3. `matrix.py`: el diccionario de las 16 combinaciones y un test parametrizado por fila.
4. `score.py`, con los tests escritos antes que el código:
   - los 5 valores calculados a mano: 98.6, 86.3, 60.8, 59.0 y 32.7;
   - el ejemplo de renormalización, que da 100;
   - RW = 0 en los CVE de fuera del KEV;
   - que los pesos suman 100.
5. `prioritize.py` (CLI): carga, cruza, ordena y genera JSON y Markdown, con el resumen de `needs_review` y el modo `--offline`.

**Hito:** `python prioritize.py --offline` reproduce la tabla de la sección 6 y pasan todos los tests.

### Semana 2 (3 – 9 nov): datos reales y evaluación
1. Scripts de descarga con caché, separados del núcleo:
   - EPSS a fecha T (`?date=2026-04-01`);
   - CVSS-B de NVD (con una API key gratuita, el límite de peticiones es más alto);
   - SSVC de Vulnrichment.
2. El conjunto de CVE: unos cientos publicados antes de T, mezclando CVE del KEV y de fuera. **Riesgo principal del proyecto:** empezar con pocos.
3. `generate_dataset.py`: entre 200 y 500 activos con semilla fija.
4. `evaluate.py`:
   - las 4 baselines con el mismo k;
   - precisión@k, recall@k y el nº de parches para cubrir el 80 % del oráculo;
   - la sensibilidad con las 4 configuraciones de pesos;
   - el efecto de la exposición.

**Decisiones antes de empezar:** tamaño del conjunto de CVE y valores de k (por ejemplo 10, 50 y 100).

**Hito:** una tabla de resultados que se reproduce con un solo comando.

### Semana 3 (10 – 16 nov): análisis y presentación
1. Una gráfica de precisión@k o recall@k por baseline.
2. README: problema, pregunta, resultados, limitaciones y qué he aprendido.
3. Si da tiempo, `advisories_no_cve.toml` con el caso de LiteLLM.
4. Revisión de que no hay datos reales. Fila del índice en "Terminado".

## Evolución — de datos sintéticos a una red real

```
 Fuentes                    Normalización               Núcleo (v0)        Salida
 tráfico (Zeek, PCAP) ─┐
 escaneo (nmap -sV)  ──┼──► assets.json  ──► cruce  ──► tier + score ──► informe,
 CMDB / CSV empresa  ──┤    (dedup, fuente,  software→CVE   (sin cambios)    cambios entre
 SBOM (syft)         ──┘     confianza)     + KEV/EPSS/CVSS                  ejecuciones, alertas
```

| Fase | Colector | Qué aporta | Dónde probarlo |
|---|---|---|---|
| **v1.5** | XML de `nmap -sV` → CPE → rangos de NVD | Servicios de red con versión. Sustituye a `findings.json` sintético. Es lo más parecido a `scan.py` | Laboratorio VirtualBox, contra la VM de Windows 11 |
| **v2** | SBOM (`syft`) → OSV (`api.osv.dev`) | Paquetes y versiones exactas, con advisories con y sin CVE (PYSEC, GHSA). Cubre el caso de LiteLLM | Una VM del laboratorio con Python y contenedores |
| **v2.5** | CSV de CMDB o de la empresa | `criticality`, propietario y entorno (prod/dev). No se puede deducir del tráfico | CSV sintético |
| **v3** | Tráfico pasivo (Zeek: `conn.log`, `software.log`) | Inventario de hosts y servicios. **Exposición con evidencia**: conexiones entrantes desde IPs públicas | Zeek en la Kali capturando el tráfico del laboratorio |
| **v3.5** | Ejecución periódica | Comparar con la ejecución anterior y avisar de los nuevos hallazgos en tier 1 | Laboratorio |

Lo que hay que añadir al esquema al escalar:
- Cada campo indica **de qué fuente viene y con qué confianza**. No es lo mismo una versión sacada de un SBOM que una deducida de un banner.
- **Deduplicación**: el mismo host puede aparecer por IP, MAC y hostname en fuentes distintas.

Limitaciones conocidas:
- Con TLS, el tráfico apenas muestra versiones.
- `nmap` no ve el software que no escucha en ningún puerto.
- Las cabeceras se pueden falsear.

## Reglas en todas las fases

- **Solo redes propias o con autorización escrita.** En una empresa, el tráfico contiene datos personales (RGPD) y necesita una base legal.
- **El modo `--offline` es obligatorio.** En una red de cliente puede no haber salida a internet, así que KEV, EPSS y NVD van en caché.
- **No reconstruir escáneres.** Tiene más valor leer la salida de nmap, Greenbone/OpenVAS o DefectDojo que intentar sustituirlos. Lo que aporta la herramienta es la priorización explicable.
