import pytest
from threat_intel.feeds import urlhaus_recent_urls


@pytest.mark.integration
def test_urlhaus_recent_urls_contract(tmp_path, monkeypatch):
    # cache vacia para forzar llamada en vivo
    monkeypatch.setattr("threat_intel.feeds.CACHE_DIR", tmp_path)

    result = urlhaus_recent_urls(limit=5)

    # la funcion traga errores y devuelve [], asi que lista vacia = fallo
    assert isinstance(result, list)
    assert result, "URLhaus no devolvio URLs"

    assert "url" in result[0]