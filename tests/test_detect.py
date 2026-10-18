import pytest

from hunter.dataset import generate_synthetic, write_dataset, load_netflow, load_auth
from hunter.detect import score_conversations
from hunter.features import conversation_features, FEATURE_NAMES


def test_generation_deterministic():
    nf1, au1 = generate_synthetic(seed=42)
    nf2, au2 = generate_synthetic(seed=42)
    assert len(nf1) == len(nf2) and len(au1) == len(au2)
    assert nf1[100]["dst_ip"] == nf2[100]["dst_ip"]


def test_roundtrip(tmp_path):
    nf, au = generate_synthetic()
    write_dataset(nf, au, tmp_path)
    nf2 = load_netflow(tmp_path / "sample_netflow.csv")
    au2 = load_auth(tmp_path / "sample_auth.jsonl")
    assert len(nf2) == len(nf)
    assert len(au2) == len(au)
    assert nf2[0]["dst_port"] == nf[0]["dst_port"]


def test_features_shape():
    nf, _ = generate_synthetic()
    convs = conversation_features(nf)
    assert convs
    c = convs[0]
    for name in FEATURE_NAMES:
        assert name in c
    assert all(k in c for k in ("src_ip", "dst_ip", "dst_port"))


def test_isolation_forest_flags_beacon():
    nf, _ = generate_synthetic()
    convs = conversation_features(nf)
    scored = score_conversations(convs)
    outliers = [c for c in scored if c["is_outlier"]]
    assert outliers, "expected at least one outlier"
    # The planted beacon conversation must be among the top outliers.
    top_n = max(5, len(outliers))
    top = scored[:top_n]
    assert any(c["dst_ip"] == "203.0.113.66" and c["dst_port"] == 443 for c in top)


def test_scoring_needs_data():
    with pytest.raises(ValueError):
        score_conversations([{"src_ip": "a", "dst_ip": "b", "dst_port": 1,
                              "flows": 1, "total_bytes": 1, "distinct_hours": 1,
                              "interarrival_cv": 1.0, "offhours_ratio": 0.0,
                              "mean_bytes_out": 1.0}] * 3)
