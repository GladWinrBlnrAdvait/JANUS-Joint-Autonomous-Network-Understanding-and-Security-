import json
import pytest
from evidence.scope import AuthorizedScope, ScopeError
from analyzers.network.nmap_analyzer import run_nmap_xml


@pytest.fixture
def scope():
    return AuthorizedScope(["192.168.56.0/24", "lab.local"])


def test_ip_and_hostname_matching(scope):
    assert scope.is_allowed("192.168.56.10")
    assert scope.is_allowed("192.168.56.0/25")      # sub-range of allowed net
    assert scope.is_allowed("LAB.local")
    assert not scope.is_allowed("192.168.57.10")
    assert not scope.is_allowed("192.168.0.0/16")   # bigger than allowed
    assert not scope.is_allowed("8.8.8.8")
    assert not scope.is_allowed("evil.example.com")


def test_require_raises(scope):
    scope.require("192.168.56.10")
    with pytest.raises(ScopeError):
        scope.require("10.0.0.1")


def test_empty_scope_refused():
    with pytest.raises(ValueError):
        AuthorizedScope([])


def test_from_file(tmp_path):
    f = tmp_path / "scope.json"
    f.write_text(json.dumps({"allowed": ["10.0.0.0/8"]}))
    assert AuthorizedScope.from_file(str(f)).is_allowed("10.1.2.3")


def test_nmap_refuses_out_of_scope_before_running(scope):
    with pytest.raises(ScopeError):
        run_nmap_xml("8.8.8.8", scope=scope)