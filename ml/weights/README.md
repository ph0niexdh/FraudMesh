# Model weights (not committed)

Pretrained weights are downloaded and SHA-256 verified by:

```bash
python ml/deepfake/download_weights.py
```

See `manifest.json` for sources and licences. The Docker image runs this step at build time.
The DeepfakeBench weights are released for research / non-commercial use (CC BY-NC 4.0);
replace them with a commercially licensed detector before any production deployment —
the `DeepfakeModel` interface in `apps/api/fraudmesh/services/deepfake/models.py` is the swap point.
