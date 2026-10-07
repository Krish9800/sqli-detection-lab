"""Unit tests for sqlilab configuration and runtime settings."""

from sqlilab.config.settings import Settings, get_settings


def test_settings_default_values() -> None:
    """Test settings default values initialize correctly."""
    settings = get_settings()
    assert settings.app_name == "SQL Injection Detection Lab"
    assert settings.version == "0.1.0"
    assert settings.environment == "development"
    assert settings.anomaly_threshold == 0.65
    assert settings.entropy_threshold == 4.2
    assert settings.tautology_strict_mode is True
    assert settings.lab_port == 8080


def test_custom_settings_instantiation() -> None:
    """Test custom configuration instances override defaults properly."""
    custom = Settings(
        app_name="Custom SQLi Detector",
        anomaly_threshold=0.8,
        tautology_strict_mode=False,
    )
    assert custom.app_name == "Custom SQLi Detector"
    assert custom.anomaly_threshold == 0.8
    assert custom.tautology_strict_mode is False
