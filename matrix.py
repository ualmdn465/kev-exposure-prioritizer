"""Tier, plazo y triage forense según la matriz de BOD 26-04.

Ver DESIGN.md, sección 4.
"""

# (expuesto, kev, automatizable, impacto_total) -> (tier, días, triage)
# días = None significa "siguiente actualización programada".
MATRIX = {
    (True, True, True, True): (1, 3, True),          # fila 1
    (True, True, True, False): (1, 3, False),        # fila 2
    (True, True, False, True): (1, 3, True),         # fila 3
    (True, True, False, False): (2, 14, False),      # fila 4
    (True, False, True, True): (1, 3, False),        # fila 5
    (True, False, True, False): (2, 14, False),      # fila 6
    (True, False, False, True): (2, 14, False),      # fila 7
    (True, False, False, False): (3, 60, False),     # fila 8
    (False, True, True, True): (1, 3, True),         # fila 9
    (False, True, True, False): (2, 14, False),      # fila 10
    (False, True, False, True): (2, 14, False),      # fila 11
    (False, True, False, False): (2, 14, False),     # fila 12
    (False, False, True, True): (3, 60, False),      # fila 13
    (False, False, True, False): (3, 60, False),     # fila 14
    (False, False, False, True): (4, None, False),   # fila 15
    (False, False, False, False): (4, None, False),  # fila 16
}

VALID_IMPACTS = ("total", "partial")


def classify(exposed: bool, in_kev: bool, automatable, technical_impact) -> dict:
    """Devuelve el tier, el plazo y si hace falta triage forense.

    automatable puede ser True, False o None.
    technical_impact puede ser "total", "partial" o None.
    Si falta un dato (None), se usa el peor caso y se apunta en "missing".
    """
    missing = []

    # Peor caso: si no se sabe, se supone automatizable.
    if automatable is None:
        missing.append("automatable")
        automatable = True

    # Peor caso: si no se sabe, se supone impacto total.
    if technical_impact is None:
        missing.append("technical_impact")
        technical_impact = "total"
    elif technical_impact not in VALID_IMPACTS:
        raise ValueError(
            f"technical_impact debe ser 'total', 'partial' o None: {technical_impact!r}"
        )

    is_total = technical_impact == "total"
    tier, days, triage = MATRIX[(exposed, in_kev, automatable, is_total)]

    return {
        "tier": tier,
        "deadline_days": days,
        "forensic_triage": triage,
        "missing": missing,
    }
