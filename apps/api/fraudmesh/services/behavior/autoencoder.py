"""Autoencoder anomaly scorer (importable so trained artifacts can be unpickled)."""

from __future__ import annotations

import numpy as np
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler


class AutoencoderScorer:
    """Reconstruction-error anomaly scorer (higher = more anomalous). Per-feature
    reconstruction error doubles as the explanation of *what* was unusual."""

    def __init__(self, seed: int):
        self.scaler = StandardScaler()
        self.net = MLPRegressor(hidden_layer_sizes=(6, 3, 6), activation="tanh", max_iter=400, random_state=seed)

    def fit(self, X):
        Z = self.scaler.fit_transform(X)
        self.net.fit(Z, Z)
        return self

    def feature_errors(self, X) -> np.ndarray:
        Z = self.scaler.transform(X)
        return (self.net.predict(Z) - Z) ** 2

    def score(self, X) -> np.ndarray:
        return self.feature_errors(X).mean(axis=1)
