import pytest


def pytest_addoption(parser):
    parser.addoption("--cov", action="store", default=None, nargs="?")
    parser.addoption("--cov-report", action="append", default=[])
    parser.addoption("--cov-fail-under", action="store", default=0, type=float)
