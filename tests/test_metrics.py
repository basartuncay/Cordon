from evals.metrics import wilson_interval


def test_wilson_interval_zero_n_is_zero_everywhere():
    ci = wilson_interval(0, 0)
    assert ci.point == ci.low == ci.high == 0.0


def test_wilson_interval_point_estimate_matches_raw_rate():
    ci = wilson_interval(5, 10)
    assert ci.point == 0.5


def test_wilson_interval_bounds_are_ordered_and_within_unit_interval():
    ci = wilson_interval(7, 34)
    assert 0.0 <= ci.low <= ci.point <= ci.high <= 1.0


def test_wilson_interval_widens_for_smaller_n_at_same_rate():
    small = wilson_interval(1, 2)
    large = wilson_interval(50, 100)
    assert (small.high - small.low) > (large.high - large.low)


def test_wilson_interval_all_successes_low_bound_is_below_one_for_finite_n():
    ci = wilson_interval(10, 10)
    assert ci.point == 1.0
    assert ci.high == 1.0
    assert 0.0 < ci.low < 1.0
