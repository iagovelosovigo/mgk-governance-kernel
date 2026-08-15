"""Pytest plugin for the frozen exam's intentionally shared function fixtures."""

from hypothesis import HealthCheck, settings


def pytest_configure(config):
    settings.register_profile(
        "mgk-independent",
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    settings.load_profile("mgk-independent")
