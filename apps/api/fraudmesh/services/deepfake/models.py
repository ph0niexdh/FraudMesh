"""Deepfake classifiers behind one replaceable interface.

Implementations (both pretrained, both public, neither invented here):

* ``EfficientNetB4Deepfake`` — EfficientNet-B4 binary real/fake classifier trained on
  FaceForensics++ (c23) by the DeepfakeBench project (Yan et al., NeurIPS 2023
  Datasets & Benchmarks). Weights: DeepfakeBench release v1.0.1 ``effnb4_best.pth``.
  Architecture reproduced exactly from DeepfakeBench ``networks/efficientnetb4.py``
  (unpadded 3x3 stem, avg-pool, Linear(1792, 2)); input 256x256 RGB, mean=std=0.5.
* ``Meso4Deepfake`` — MesoNet-4 (Afchar et al., WIFS 2018), same benchmark and
  preprocessing; ~28k parameters. Used as the lightweight fallback.

Both expose ``predict(faces) -> list[FacePrediction]`` and ``gradcam(face)``. The
pipeline and the UI do not know which one is active.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

INPUT_SIZE = 256


@dataclass
class FacePrediction:
    deepfake_probability: float
    real_probability: float
    logit_margin: float


@dataclass
class ModelCard:
    name: str
    version: str
    architecture: str
    training_data: str
    source: str
    license: str
    input_size: int
    params: int
    weights_sha256: str
    reported_metrics: dict


class DeepfakeModel(ABC):
    card: ModelCard

    @abstractmethod
    def predict(self, faces_rgb: list[np.ndarray]) -> list[FacePrediction]:
        """faces_rgb: list of HxWx3 uint8 RGB face crops (any size; resized internally)."""

    @abstractmethod
    def gradcam(self, face_rgb: np.ndarray) -> np.ndarray:
        """Return a [0,1] heatmap (INPUT_SIZE x INPUT_SIZE) of regions that pushed the
        prediction towards 'fake'. Attribution aid only — not proof of manipulation."""


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class _TorchDeepfake(DeepfakeModel):
    """Shared torch plumbing: preprocessing, batched inference, Grad-CAM."""

    def __init__(self, weights: Path, threads: int):
        import torch

        torch.set_num_threads(max(1, threads))
        self._torch = torch
        self._lock = threading.Lock()  # torch modules are not re-entrant for Grad-CAM hooks
        self.net = self._build()
        state = torch.load(weights, map_location="cpu", weights_only=True)
        state = {k.removeprefix("backbone."): v for k, v in state.items()}
        self.net.load_state_dict(state, strict=True)  # raises on any architecture mismatch
        self.net.eval()
        self._weights_sha = _sha256(weights)

    @abstractmethod
    def _build(self): ...

    @abstractmethod
    def _cam_module(self): ...

    def _tensor(self, faces_rgb: list[np.ndarray]):
        import cv2

        torch = self._torch
        arr = np.stack([cv2.resize(f, (INPUT_SIZE, INPUT_SIZE), interpolation=cv2.INTER_LINEAR) for f in faces_rgb])
        x = torch.from_numpy(arr).permute(0, 3, 1, 2).float().div_(255.0)
        return (x - 0.5) / 0.5  # DeepfakeBench normalisation (mean=std=0.5)

    def predict(self, faces_rgb: list[np.ndarray]) -> list[FacePrediction]:
        if not faces_rgb:
            return []
        torch = self._torch
        with self._lock, torch.inference_mode():
            logits = self.net(self._tensor(faces_rgb))
            probs = torch.softmax(logits, dim=1)
        out = []
        for p, lg in zip(probs.tolist(), logits.tolist()):
            out.append(FacePrediction(deepfake_probability=float(p[1]), real_probability=float(p[0]), logit_margin=float(lg[1] - lg[0])))
        return out

    def gradcam(self, face_rgb: np.ndarray) -> np.ndarray:
        import cv2

        torch = self._torch
        acts: dict = {}

        def fwd_hook(_m, _i, o):
            acts["a"] = o
            o.register_hook(lambda g: acts.__setitem__("g", g))

        with self._lock:
            handle = self._cam_module().register_forward_hook(fwd_hook)
            try:
                x = self._tensor([face_rgb]).requires_grad_(False)
                with torch.enable_grad():
                    logits = self.net(x)
                    self.net.zero_grad(set_to_none=True)
                    (logits[0, 1] - logits[0, 0]).backward()
            finally:
                handle.remove()
        a, g = acts["a"][0].detach(), acts["g"][0].detach()
        weights = g.mean(dim=(1, 2), keepdim=True)
        cam = torch.relu((weights * a).sum(0)).numpy()
        if cam.max() > 0:
            cam = cam / cam.max()
        return cv2.resize(cam.astype(np.float32), (INPUT_SIZE, INPUT_SIZE), interpolation=cv2.INTER_CUBIC).clip(0, 1)


class EfficientNetB4Deepfake(_TorchDeepfake):
    WEIGHTS = "effnb4_best.pth"

    def __init__(self, weights: Path, threads: int = 4):
        super().__init__(weights, threads)
        self.card = ModelCard(
            name="deepfake-detector",
            version="effnb4-ffpp-c23-v1.0.1",
            architecture="EfficientNet-B4 (DeepfakeBench)",
            training_data="FaceForensics++ c23 (DeepfakeBench protocol)",
            source="https://github.com/SCLBD/DeepfakeBench (release v1.0.1, effnb4_best.pth)",
            license="DeepfakeBench weights: CC BY-NC 4.0 (research / non-commercial)",
            input_size=INPUT_SIZE,
            params=sum(p.numel() for p in self.net.parameters()),
            weights_sha256=self._weights_sha,
            reported_metrics={
                "benchmark": "DeepfakeBench (published leaderboard, frame-level AUC)",
                "note": "Generalisation to unseen manipulation methods is substantially lower than in-domain AUC.",
            },
        )

    def _build(self):
        import torch.nn as nn
        import torch.nn.functional as F
        from efficientnet_pytorch import EfficientNet

        class Net(nn.Module):
            def __init__(self):
                super().__init__()
                self.efficientnet = EfficientNet.from_name("efficientnet-b4")
                self.efficientnet._conv_stem = nn.Conv2d(3, 48, kernel_size=3, stride=2, bias=False)
                self.efficientnet._fc = nn.Identity()
                self.last_layer = nn.Linear(1792, 2)

            def forward(self, x):
                f = self.efficientnet.extract_features(x)
                return self.last_layer(F.adaptive_avg_pool2d(f, (1, 1)).flatten(1))

        return Net()

    def _cam_module(self):
        return self.net.efficientnet._bn1


class Meso4Deepfake(_TorchDeepfake):
    WEIGHTS = "meso4_best.pth"

    def __init__(self, weights: Path, threads: int = 4):
        super().__init__(weights, threads)
        self.card = ModelCard(
            name="deepfake-detector-lite",
            version="meso4-ffpp-c23-v1.0.1",
            architecture="MesoNet-4 (DeepfakeBench)",
            training_data="FaceForensics++ c23 (DeepfakeBench protocol)",
            source="https://github.com/SCLBD/DeepfakeBench (release v1.0.1, meso4_best.pth)",
            license="DeepfakeBench weights: CC BY-NC 4.0 (research / non-commercial)",
            input_size=INPUT_SIZE,
            params=sum(p.numel() for p in self.net.parameters()),
            weights_sha256=self._weights_sha,
            reported_metrics={"note": "Lightweight fallback; markedly weaker than EfficientNet-B4."},
        )

    def _build(self):
        import torch.nn as nn

        class Net(nn.Module):  # DeepfakeBench networks/mesonet.py :: Meso4 (eval path)
            def __init__(self):
                super().__init__()
                self.conv1 = nn.Conv2d(3, 8, 3, padding=1, bias=False)
                self.bn1 = nn.BatchNorm2d(8)
                self.relu = nn.ReLU(inplace=False)
                self.leakyrelu = nn.LeakyReLU(0.1)
                self.conv2 = nn.Conv2d(8, 8, 5, padding=2, bias=False)
                self.bn2 = nn.BatchNorm2d(16)
                self.conv3 = nn.Conv2d(8, 16, 5, padding=2, bias=False)
                self.conv4 = nn.Conv2d(16, 16, 5, padding=2, bias=False)
                self.maxpooling1 = nn.MaxPool2d(kernel_size=(2, 2))
                self.maxpooling2 = nn.MaxPool2d(kernel_size=(4, 4))
                self.dropout = nn.Dropout2d(0.5)
                self.fc1 = nn.Linear(16 * 8 * 8, 16)
                self.fc2 = nn.Linear(16, 2)

            def forward(self, x):
                x = self.maxpooling1(self.bn1(self.relu(self.conv1(x))))
                x = self.maxpooling1(self.bn1(self.relu(self.conv2(x))))
                x = self.maxpooling1(self.bn2(self.relu(self.conv3(x))))
                x = self.maxpooling2(self.bn2(self.relu(self.conv4(x))))
                x = x.flatten(1)
                x = self.dropout(x)
                x = self.leakyrelu(self.fc1(x))
                x = self.dropout(x)
                return self.fc2(x)

        return Net()

    def _cam_module(self):
        return self.net.conv4


def load_model(model_dir: Path, preference: str = "auto", threads: int = 4) -> DeepfakeModel | None:
    """Pick the strongest available model. Returns None when no weights are present
    (the deepfake engine then reports OFFLINE instead of inventing scores)."""
    candidates: list[type[_TorchDeepfake]]
    if preference == "meso4":
        candidates = [Meso4Deepfake]
    elif preference == "effnb4":
        candidates = [EfficientNetB4Deepfake]
    else:
        candidates = [EfficientNetB4Deepfake, Meso4Deepfake]
    for cls in candidates:
        path = model_dir / cls.WEIGHTS
        if path.exists():
            try:
                model = cls(path, threads)
                logger.info("deepfake model loaded", extra={"fields": {"model": model.card.version}})
                return model
            except Exception:
                logger.exception("failed to load deepfake model", extra={"fields": {"weights": str(path)}})
    return None
