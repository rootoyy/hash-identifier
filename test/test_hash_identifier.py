import pytest
from src.hash_identifier import HashIdentifier, Confidence

@pytest.fixture
def identifier():
    return HashIdentifier()

def test_bcrypt_prefix(identifier):
    results = identifier.identify("$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G.VHvgvWK")
    assert len(results) == 1
    assert results[0].name == "Bcrypt"
    assert results[0].confidence == Confidence.HIGH

def test_md5_length(identifier):
    results = identifier.identify("5f4dcc3b5aa765d61d8327deb882cf99")
    names = [r.name for r in results]
    assert "MD5" in names