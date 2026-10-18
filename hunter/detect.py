"""ML-assisted anomaly scoring via Isolation Forest.

Scores each conversation feature vector; returns conversations ranked by
anomaly score. This is a triage aid: high scores mean "look here first",
never "block automatically".
"""

from __future__ import annotations

from sklearn.ensemble import IsolationForest

from .features import feature_vector


def score_conversations(convs: list[dict], contamination: float = 0.05,
                        seed: int = 42) -> list[dict]:
    """Attach anomaly_score/-flag to each conversation, return ranked list.

    sklearn's decision_function is higher = more normal, so we expose
    anomaly_score = -decision_function (higher = more anomalous).
    """
    if len(convs) < 5:
        raise ValueError("need at least 5 conversations to score")
    X = [feature_vector(c) for c in convs]
    forest = IsolationForest(contamination=contamination, random_state=seed)
    flags = forest.fit_predict(X)           # -1 = outlier
    raw = forest.decision_function(X)       # higher = more normal

    scored = []
    for c, flag, r in zip(convs, flags, raw):
        scored.append({
            **c,
            "anomaly_score": round(float(-r), 4),
            "is_outlier": bool(flag == -1),
        })
    scored.sort(key=lambda c: c["anomaly_score"], reverse=True)
    return scored
