"""Shared test fixtures for OT Asset Discovery test suite."""

import pytest
from hypothesis import settings

# Configure Hypothesis for local development (100 examples)
# CI should override with @settings(max_examples=500)
settings.register_profile("dev", max_examples=100)
settings.register_profile("ci", max_examples=500)
settings.load_profile("dev")
