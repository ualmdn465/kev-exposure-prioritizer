"""Tests de la matriz de BOD 26-04 (DESIGN.md, sección 4).

Cada fila de ROWS es una fila de la tabla del DESIGN.md. Si la Table 1
oficial cambia alguna, se cambia aquí y en MATRIX a la vez.
"""
import pytest

from matrix import MATRIX, classify


# expuesto, kev, automatizable, impacto, tier, días, triage
ROWS = [
    (True,  True,  True,  "total",   1, 3,    True),   # 1
    (True,  True,  True,  "partial", 1, 3,    False),  # 2
    (True,  True,  False, "total",   1, 3,    True),   # 3
    (True,  True,  False, "partial", 2, 14,   False),  # 4
    (True,  False, True,  "total",   1, 3,    False),  # 5
    (True,  False, True,  "partial", 2, 14,   False),  # 6
    (True,  False, False, "total",   2, 14,   False),  # 7
    (True,  False, False, "partial", 3, 60,   False),  # 8
    (False, True,  True,  "total",   1, 3,    True),   # 9
    (False, True,  True,  "partial", 2, 14,   False),  # 10
    (False, True,  False, "total",   2, 14,   False),  # 11
    (False, True,  False, "partial", 2, 14,   False),  # 12
    (False, False, True,  "total",   3, 60,   False),  # 13
    (False, False, True,  "partial", 3, 60,   False),  # 14
    (False, False, False, "total",   4, None, False),  # 15
    (False, False, False, "partial", 4, None, False),  # 16
]


def test_matrix_has_16_rows():
    assert len(MATRIX) == 16


@pytest.mark.parametrize(
    "exposed, in_kev, automatable, impact, tier, days, triage", ROWS
)
def test_each_row(exposed, in_kev, automatable, impact, tier, days, triage):
    result = classify(exposed, in_kev, automatable, impact)

    assert result["tier"] == tier
    assert result["deadline_days"] == days
    assert result["forensic_triage"] is triage
    assert result["missing"] == []


def test_missing_values_use_worst_case():
    """host-f: expuesto, en KEV y sin automatable ni technical_impact.
    El peor caso (sí y total) lo lleva a la fila 1.
    """
    result = classify(True, True, None, None)

    assert result["tier"] == 1
    assert result["deadline_days"] == 3
    assert result["forensic_triage"] is True
    assert result["missing"] == ["automatable", "technical_impact"]


def test_worst_case_does_not_always_raise_the_tier():
    """Sin exposición, sin KEV y no automatizable, el impacto total
    también da tier 4 (fila 15). Lo que falta se marca igualmente.
    """
    result = classify(False, False, False, None)

    assert result["tier"] == 4
    assert result["missing"] == ["technical_impact"]


@pytest.mark.parametrize("bad_impact", ["parcial", "TOTAL", "", 1])
def test_invalid_impact_raises(bad_impact):
    """Un valor mal escrito no puede convertirse en silencio en 'partial'."""
    with pytest.raises(ValueError):
        classify(True, True, True, bad_impact)
