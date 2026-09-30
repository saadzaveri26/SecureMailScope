"""Test fixtures: isolated artifacts dir + freshly generated synthetic captures."""
import os
import sys
import tempfile
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
_TMP = Path(tempfile.mkdtemp(prefix="sms_test_"))
os.environ["SMS_ARTIFACTS_DIR"] = str(_TMP)
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import pytest  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402


@pytest.fixture(scope="session")
def artifacts():
    from app import config
    config.ensure_dirs()
    import generate_sample_pcaps as g
    pki = g.make_pki()
    (config.TRUST_STORE_DIR / "SyntheticCorpRootCA.pem").write_bytes(pki["root"].public_bytes(serialization.Encoding.PEM))
    g.build_baseline(pki, config.SAMPLES_DIR / "baseline.pcap")
    g.build_drift(pki, config.SAMPLES_DIR / "drift.pcap")
    return config.SAMPLES_DIR
