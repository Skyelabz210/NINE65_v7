"""Bounded target-query constructor, with authentic readings as a premise.

No full day count or persistent winding is an input. Runtime checks establish
canonical ranges and shared-modulus compatibility, not measurement provenance.
"""


def _canonical(value, modulus):
    if type(value) is not int or not 0 <= value < modulus:
        raise ValueError(f'canonical integer residue modulo {modulus} required')


def eclipse_phase(r260, v584, w23):
    """Return X mod 11960 from X mod 260, 584, 23.

    All readings must refer to the same integer model, origin and epoch.
    The target is the idealized 11960-day phase, not an eclipse prediction.
    """
    for value, modulus in ((r260, 260), (v584, 584), (w23, 23)):
        _canonical(value, modulus)
    difference = v584 - r260
    if difference % 4:
        raise ValueError('260 and 584 readings disagree modulo 4')
    r520 = r260 + 260 * ((difference // 4) % 2)
    k23 = (5 * (w23 - r520)) % 23
    return r520 + 520 * k23


def restore_calendar_readings(phase11960, retained73):
    """Inverse of the full frame transfer when the 73-reading is retained."""
    _canonical(phase11960, 11960)
    _canonical(retained73, 73)
    v584 = retained73 + 73 * ((phase11960 - retained73) % 8)
    return phase11960 % 260, v584, phase11960 % 23
