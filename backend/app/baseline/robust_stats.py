from collections.abc import Iterable

import numpy as np


def median_absolute_deviation(values: Iterable[float]) -> float:
    array = np.asarray(list(values), dtype=float)
    if array.size == 0:
        return 0.0
    median = float(np.median(array))
    return float(np.median(np.abs(array - median)))


def robust_z_score(value: float, values: Iterable[float]) -> float:
    array = np.asarray(list(values), dtype=float)
    if array.size < 3:
        return 0.0
    median = float(np.median(array))
    mad = median_absolute_deviation(array)
    if mad == 0:
        return 0.0 if value == median else 3.5
    return abs(0.6745 * (value - median) / mad)


def trimmed(values: Iterable[float], fraction: float = 0.1) -> list[float]:
    array = sorted(float(value) for value in values)
    trim_count = int(len(array) * fraction)
    return array[trim_count:len(array) - trim_count] if len(array) > trim_count * 2 else array
