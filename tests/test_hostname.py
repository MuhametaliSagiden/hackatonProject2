from radar.analysis import _hostname_matches


def test_wildcard_matches_exactly_one_label():
    assert _hostname_matches("x.example.com", "*.example.com")
    assert not _hostname_matches("example.com", "*.example.com")
    assert not _hostname_matches("x.y.example.com", "*.example.com")
