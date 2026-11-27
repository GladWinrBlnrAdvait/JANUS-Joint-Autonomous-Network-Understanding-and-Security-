"""Functional check: ordinary arithmetic still works."""
import app


def test_basic_arithmetic():
    assert app.calculate("2+3*4") == 14
    assert app.calculate("(1+2)*3") == 9
    assert app.calculate("10/4") == 2.5
    assert app.calculate("-3+5") == 2
