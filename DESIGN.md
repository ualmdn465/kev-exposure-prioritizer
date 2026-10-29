# DESIGN — Priorizador KEV + exposición (v0)

> Estado: diseño cerrado para empezar a programar. Queda un **TODO**: contrastar la matriz de la sección 4 con el texto oficial de cisa.gov.

## 1. Objetivo

Ordenar los hallazgos (activo, CVE) de un inventario según cuándo hay que corregirlos y explicar por qué, para después comparar ese orden con priorizar solo por CVSS, solo por EPSS o solo por KEV.

## 2. Entradas

Todos los activos son sintéticos (`host-a`, `host-b`…). No hay IPs, hostnames reales ni credenciales.

### A. Activos — `assets.json`

Es tu `inventory_synthetic.json` con tres campos más. Se mantiene `host` para reutilizar `load_inventory()`.

| Campo | Tipo | Ejemplo | Notas |
|---|---|---|---|
| `host` | str | `"host-a"` | Identificador único |
| `vendor` | str | `"Fortinet"` | Ya existía |
| `product` | str | `"FortiOS"` | Ya existía |
| `version` | str | `"7.2.0"` | Ya existía. Se usará con los advisories sin CVE (v2) |
| `criticality` | int 1-5 | `5` | **Nuevo, obligatorio.** 5 = negocio crítico |
| `internet_facing` | bool | `true` | **Nuevo, obligatorio** |
| `exposed_ports` | list[int] | `[443]` | **Nuevo, opcional.** En v0 solo aparece en `reasons` y no suma al score |

`criticality` e `internet_facing` son datos propios de la organización. Si faltan, el fichero se rechaza con código de salida 2, como ya hace `load_inventory()`. No es un hallazgo con datos incompletos: es una entrada mal formada.

`exposed_ports` no suma al score porque la exposición ya la recoge `internet_facing`; sumar también los puertos contaría la misma señal dos veces. Además, `scan.py` solo escanea loopback.

### B. Hallazgos — `findings.json`

Simula la salida de un escáner de vulnerabilidades: `[{"host": "host-a", "cve": "CVE-2024-21762"}, ...]`

Por qué es un fichero aparte:
1. El KEV no trae versiones afectadas. Con el cruce de `kev_enrich.py` todos los hallazgos son `candidate`, y `host-d` acumula 209 por culpa de `Windows`.
2. La baseline CVSS necesita también CVE que **no** están en el KEV, y esos no salen del cruce con el KEV.

### C. KEV — catálogo de CISA

Se lee con `load_kev()` y `fetch_kev()` de `kev_enrich.py` (validación, caché y `--offline` ya hechos). Campos que se usan:

| Campo | Tipo real en el JSON | Uso |
|---|---|---|
| `cveID` | str | Clave de cruce con B |
| `dateAdded` | str `AAAA-MM-DD` | Corte temporal en la evaluación |
| `knownRansomwareCampaignUse` | str `"Known"` / `"Unknown"` | Señal del score (**no es bool**) |
| `forensicTriage` | str `"Yes"` / `"No"` | Se muestra en `reasons` |

### D. Datos por CVE — `cve_info.json`

```json
{"CVE-2024-21762": {"cvss": 9.8, "epss": 0.94, "automatable": true, "technical_impact": "total"}}
```

| Campo | Tipo | Fuente real (en v1 se rellena a mano o de forma sintética) |
|---|---|---|
| `cvss` | float 0-10 o null | NVD (muchos CVE recientes aún no tienen) |
| `epss` | float 0-1 o null | FIRST.org. La API admite `date=AAAA-MM-DD` para pedir valores históricos |
| `automatable` | bool o null | SSVC de CISA (Vulnrichment) |
| `technical_impact` | `"total"` / `"partial"` / null | SSVC de CISA (Vulnrichment) |

Vulnrichment solo cubre una parte de los CVE, así que los `null` en `automatable` y `technical_impact` serán frecuentes. La regla de la sección 4 está pensada para eso.

## 3. Salida

Una lista ordenada por `(tier asc, priority_score desc)`:

```json
{"host": "host-a", "cve": "CVE-2024-21762", "tier": 1, "deadline_days": 3,
 "forensic_triage": true, "priority_score": 98.6, "needs_review": false,
 "reasons": ["en KEV", "ransomware conocido", "expuesto a internet", "..."]}
```

`deadline_days` es `null` en el tier 4 (siguiente actualización programada).

## 4. Tiers (matriz de BOD 26-04)

BOD 26-04 (10 de junio de 2026) sustituye a BOD 22-01. Cruza cuatro variables binarias por hallazgo y da 16 combinaciones. La tabla está tomada de la reproducción de Nucleus Security.

**TODO:** contrastarla con el texto oficial antes de citarla. La URL está en el campo `notes` de tu `kev_sample.json`: `https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk`.

| # | Expuesto | KEV | Automatizable | Impacto | Plazo | Triage forense | Tier |
|---|---|---|---|---|---|---|---|
| 1 | sí | sí | sí | total | 3 días | sí | 1 |
| 2 | sí | sí | sí | parcial | 3 días | no | 1 |
| 3 | sí | sí | no | total | 3 días | sí | 1 |
| 4 | sí | sí | no | parcial | 14 días | no | 2 |
| 5 | sí | no | sí | total | 3 días | no | 1 |
| 6 | sí | no | sí | parcial | 14 días | no | 2 |
| 7 | sí | no | no | total | 14 días | no | 2 |
| 8 | sí | no | no | parcial | 60 días | no | 3 |
| 9 | no | sí | sí | total | 3 días | sí | 1 |
| 10 | no | sí | sí | parcial | 14 días | no | 2 |
| 11 | no | sí | no | total | 14 días | no | 2 |
| 12 | no | sí | no | parcial | 14 días | no | 2 |
| 13 | no | no | sí | total | 60 días | no | 3 |
| 14 | no | no | sí | parcial | 60 días | no | 3 |
| 15 | no | no | no | total | Siguiente actualización | no | 4 |
| 16 | no | no | no | parcial | Siguiente actualización | no | 4 |

Cosas que se ven en la tabla:
- **Un CVE del KEV nunca baja de 14 días.**
- **Un CVE que no está en el KEV puede tener 3 días** (fila 5: expuesto, automatizable y con impacto total).
- El triage forense aparece cuando hay KEV e impacto total y además el activo está expuesto o la explotación es automatizable.

**Implementación:** un diccionario `MATRIX[(expuesto, kev, automatizable, total)] → (tier, días, triage)`, sin cadenas de `if`. Es más fácil de comparar con la tabla oficial y permite un test por fila.

**Datos que faltan (`null`):**

1. **El hallazgo nunca se descarta.** Quitarlo del informe es justo lo que esconde el riesgo.
2. **El tier se calcula con el peor caso**: lo que falta cuenta como automatizable o con impacto total. Si el dato real es peor de lo que parece, el plazo ya está cubierto.
3. **Se marca `needs_review: true`** y `reasons` dice qué falta, por ejemplo `"sin technical_impact"`. Esa es la cola de revisión manual: la herramienta decide primero y una persona lo revisa después.
4. **El informe resume** cuántos hallazgos tienen datos incompletos.

Normalmente un `null` no es un dato ocultado, sino un CVE que la fuente aún no ha enriquecido (NVD lleva retraso desde 2024). Un valor **falso** es un problema distinto, de integridad de la fuente. Se trata validando la entrada y usando solo fuentes oficiales, no con esta regla.

## 5. Score (ordena dentro de cada tier)

```
score = w_kev·KEV + w_rw·RW + w_epss·EPSS + w_exp·EXP
      + w_crit·(criticality−1)/4 + w_cvss·CVSS/10
```

- `KEV`, `RW` (ransomware `"Known"`) y `EXP` (`internet_facing`) valen 0 o 1. `EPSS` va de 0 a 1.
- Cada término está entre 0 y 1 y los pesos son porcentajes que suman 100, así que el score queda entre 0 y 100 sin tener que dividir.
- **`RW` vale 0 en los CVE que no están en el KEV.** No es un dato que falta: el campo solo existe en el KEV, y si no está en el KEV no hay ransomware confirmado.
- **`KEV` cambia el orden dentro de los tiers 1 y 2**, porque según la matriz mezclan CVE del KEV y de fuera. También se usa para evaluar el score solo, sin tiers.
- Los pesos van en `weights.toml`, que se lee con `tomllib` de la librería estándar (Python ≥ 3.11). YAML obligaría a instalar PyYAML.

**Si falta `cvss` o `epss`: se renormaliza.** Se quitan los términos que faltan y se reparte su peso entre las señales conocidas:

```
score = 100 · Σ(wᵢ·xᵢ, solo conocidos) / Σ(wᵢ, solo conocidos)
```

Ejemplo: un CVE del KEV, con ransomware, expuesto, criticidad 5 y sin CVSS ni EPSS da (30 + 10 + 20 + 10) / 70 · 100 = **100**. Con `null` → 0 daría 70.

Por qué se renormaliza:
- Un 0 significaría "riesgo nulo" y hundiría justo los CVE más recientes.
- El peor caso (CVSS 10, EPSS 1) inflaría el score de todos los CVE sin datos.
- Renormalizar mantiene la proporción entre las señales conocidas.

El precio es que, con pocos datos, el score se apoya en pocas señales. Por eso esos hallazgos llevan `needs_review`.

**Configuraciones de pesos** (cada fila suma 100 %):

| Config | kev | rw | epss | exp | crit | cvss | Qué prioriza |
|---|---|---|---|---|---|---|---|
| **`base` (principal)** | 30 % | 10 % | 20 % | 20 % | 10 % | 10 % | Equilibrado: explotación confirmada primero, después predicción y exposición |
| `predictivo` | 18 % | 9 % | 27 % | 27 % | 9 % | 10 % | Probabilidad de explotación (EPSS) y exposición por encima de KEV |
| `negocio` | 25 % | 10 % | 20 % | 20 % | 20 % | 5 % | Impacto en la organización: criticidad ×2 respecto a `base` |
| `amenaza-conocida` | 35 % | 15 % | 10 % | 10 % | 25 % | 5 % | Explotación y ransomware confirmados más criticidad; la predicción queda en segundo plano |

- **`base`** es el modelo que se compara con las baselines (sección 7). Es la principal porque no lleva ninguna señal al extremo.
- **Las otras tres** sirven para el análisis de sensibilidad: si el top-k apenas cambia entre configuraciones, el resultado no depende de los pesos exactos.

**Justificación del orden en `base`:**
- **KEV (30 %):** explotación ya confirmada por CISA, que es la señal más directa de riesgo real.
- **EPSS (20 %):** FIRST lo define como la estimación de la probabilidad de que un CVE publicado se explote en los próximos 30 días. Predice lo que se quiere priorizar, pero es una estimación, no una confirmación, y por eso pesa menos que KEV.
- **Exposición (20 %):** es una de las cuatro variables de BOD 26-04, y un activo expuesto a internet lo puede atacar cualquiera.
- **Ransomware (10 %):** agrava el impacto, pero solo existe en los CVE del KEV.
- **Criticidad (10 %):** el impacto en el negocio depende del activo, no de la vulnerabilidad.
- **CVSS (10 %):** la guía de CVSS v4.0 (sección 2.2, *"CVSS Base Score Measures Severity, not Risk"*) dice que está diseñado para medir la gravedad y que no debe usarse solo para evaluar el riesgo.

Fuera de v0:
- **Antigüedad desde `dateAdded`.** Solo existe para los CVE del KEV y su efecto va en dos sentidos.
- **Encadenamiento.** El KEV no tiene un campo para eso; solo aparece como texto libre.

## 6. Ejemplo con 5 activos

Valores **sintéticos**. Los CVE son públicos, pero CVSS, EPSS, automatizable e impacto están inventados para el ejemplo.

| host | CVE | KEV | RW | expuesto | crit | cvss | epss | autom. | impacto |
|---|---|---|---|---|---|---|---|---|---|
| host-a | CVE-2024-21762 | sí | Known | sí | 5 | 9.8 | 0.94 | sí | total |
| host-b | CVE-2023-21529 | sí | Known | sí | 4 | 8.8 | 0.50 | no | total |
| host-c | CVE-2026-35273 | sí | Known | no | 3 | 9.8 | 0.30 | sí | total |
| host-d | CVE-2024-30088 | sí | Known | no | 5 | 7.0 | 0.10 | no | total |
| host-e | CVE-2099-0001 (ficticia) | no | — | sí | 2 | 9.8 | 0.02 | no | parcial |

**Cálculo con pesos `base`** (kev·30 + rw·10 + epss·20 + exp·20 + crit·10 + cvss·10):

| host | Fila de la matriz | Tier | Plazo | Triage | Score |
|---|---|---|---|---|---|
| host-a | 1 | 1 | 3 días | sí | 30 + 10 + 18.8 + 20 + 10 + 9.8 = **98.6** |
| host-b | 3 | 1 | 3 días | sí | 30 + 10 + 10 + 20 + 7.5 + 8.8 = **86.3** |
| host-c | 9 | 1 | 3 días | sí | 30 + 10 + 6 + 0 + 5 + 9.8 = **60.8** |
| host-d | 11 | 2 | 14 días | no | 30 + 10 + 2 + 0 + 10 + 7 = **59.0** |
| host-e | 8 | 3 | 60 días | no | 0 + 0 + 0.4 + 20 + 2.5 + 9.8 = **32.7** |

Criticidad: (crit − 1)/4 · 10, así que crit 4 → 7.5, crit 3 → 5 y crit 2 → 2.5.

**Comparación con priorizar solo por CVSS:** el orden sería a = c = e (9.8) > b (8.8) > d (7.0).
- `host-e` empataría en primer lugar, aunque no está en el KEV y su EPSS es de 0.02. El modelo lo deja el último, con 60 días.
- `host-d`, que está en el KEV y tiene ransomware conocido, quedaría el último por CVSS. El modelo le da 14 días.

Esa diferencia es la tesis del proyecto.

## 7. Validación

**Baselines** (todas con el mismo número de parches, k):
1. Solo CVSS
2. Solo EPSS
3. Solo KEV
4. Modelo (tier + score con pesos `base`)

**Sensibilidad:** se repite la evaluación con `predictivo`, `negocio` y `amenaza-conocida`, y se compara cuánto cambia el top-k.

**Oráculo sin circularidad (split temporal), con fecha de corte T = 2026-04-01:**
- Entrada: el KEV filtrado a `dateAdded ≤ T`.
- Oráculo: los CVE con `dateAdded > T`, es decir, explotados *después* del corte.
- Por qué esa fecha: con el catálogo `2026.10.20` (1.754 entradas), quedan **198 entradas** posteriores a T, unos 6,5 meses de test. Un corte más tardío (por ejemplo, 2026-07-01) deja solo 123.

**Reglas para no filtrar información del futuro (*data leakage*):**
- EPSS **a fecha T**, pedido con `?date=2026-04-01`. El EPSS actual ya refleja la explotación posterior a T.
- El conjunto de CVE solo incluye los publicados antes de T, porque los posteriores no se podían priorizar en T.
- Limitación aceptada: NVD puede haber cambiado el CVSS después de T, y Vulnrichment puede haber añadido `automatable` o `technical_impact` después de T. Se documenta en la memoria.
- Limitación aceptada: el oráculo solo cuenta la explotación que CISA ha confirmado, así que se queda corto respecto a la explotación real.

**Métricas:**
- precisión@k y recall@k frente al oráculo
- nº de parches necesarios para cubrir el 80 % del oráculo

**Efecto de la exposición** (se mide por activo, no por CVE): se ejecuta el modelo dos veces, una con `internet_facing` real y otra suponiendo que todo está expuesto, que es lo que pasa si no tienes inventario de exposición. La diferencia en el nº de hallazgos a 3 días es la reducción de backlog que aporta conocer la exposición. Es una métrica de carga de trabajo, no de acierto.

**Dataset:**
- 200-500 activos sintéticos con semilla fija.
- Los CVE de `findings.json` se sacan de un conjunto **real** (que incluya CVE de dentro y de fuera del KEV), para que el oráculo no lo decida el generador.

## 8. Fuera de v0

- `advisories_no_cve.toml`: casos de cadena de suministro sin CVE, como `litellm` 1.82.7/1.82.8 (PYSEC-2026-2), cruzados por paquete y versión.
- Salida CSV, puertos de `scan.py` en el score, encadenamiento de CVE.

## Fuentes

- [CISA – BOD 26-04](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk) (TODO: contrastar) y [matriz reproducida por Nucleus Security](https://nucleussec.com/blog/navigating-requirements-cisa-bod-26-04/)
- [FIRST – EPSS](https://www.first.org/epss/) y [API de EPSS](https://api.first.org/epss/)
- [FIRST – CVSS v4.0 User Guide](https://www.first.org/cvss/v4.0/user-guide), sección 2.2 (TODO: comprobar el enlace; yo leí una copia del PDF)
- [CISA – KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
