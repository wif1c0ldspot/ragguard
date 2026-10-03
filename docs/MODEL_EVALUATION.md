# Reproducing local classifier evaluation

The optional adapter supports two explicitly reviewed model identities. The
existing Meta Prompt Guard 2 configuration remains available with its original
label semantics. The additional ungated model is
[`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2),
pinned for this evaluation to revision
`90c9989b1a342275dd0d1a95aad283c04e075671`.

The publisher lists Apache-2.0 licensing and English prompt-injection
classification. Its project is now archived and no longer actively maintained.
This is a reproducible research baseline, not an endorsement of ongoing support.
The model card excludes non-English and jailbreak detection from its intended
coverage and cautions against scanning system prompts. Its reported training and
post-training metrics are not Ragguard measurements. See the
[pinned model card](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/blob/90c9989b1a342275dd0d1a95aad283c04e075671/README.md)
and [license](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/blob/90c9989b1a342275dd0d1a95aad283c04e075671/LICENSE).

## Provisioning

The base Ragguard installation is unchanged and has no ML runtime dependency.
The recorded evaluation used Python 3.12.13 on macOS arm64 with PyTorch 2.8.0,
Transformers 4.57.1 and SentencePiece 0.2.1. Exact package versions are in
[`evals/requirements-semantic.txt`](../evals/requirements-semantic.txt). These
record one environment; platform-specific wheel availability can differ.

From the repository root, create a separate runtime:

```sh
uv venv /tmp/ragguard-model-runtime --python 3.12
uv pip install --python /tmp/ragguard-model-runtime/bin/python -r evals/requirements-semantic.txt
export HF_HOME=/tmp/ragguard-model-cache
```

Download only the reviewed configuration, tokenizer, license and safetensors
files. This is an explicit provisioning step; adapter calls never download files.
It needs approximately 750 MB for the model snapshot, in addition to the runtime.
No gated-model license acceptance or inference API is involved.

```sh
/tmp/ragguard-model-runtime/bin/python - <<'PY'
from huggingface_hub import snapshot_download
snapshot_download(
    'protectai/deberta-v3-base-prompt-injection-v2',
    revision='90c9989b1a342275dd0d1a95aad283c04e075671',
    token=False,
    allow_patterns=[
        'config.json', 'model.safetensors', 'tokenizer.json',
        'tokenizer_config.json', 'special_tokens_map.json',
        'added_tokens.json', 'spm.model', 'LICENSE', 'README.md',
    ],
)
PY
```

The downloaded `model.safetensors` SHA256 was independently checked:
`6521cb8d0ac08148c81464899c424e6148fcc62befa371089fa4061d8b6e0424`.
Pickle model/training files and repository-supplied Python code are not loaded.
The adapter uses `local_files_only=True`, `trust_remote_code=False`, and
`use_safetensors=True`.

## Scores and calibration

Run scoring offline after provisioning:

```sh
HF_HUB_OFFLINE=1 /tmp/ragguard-model-runtime/bin/python - <<'PY'
import torch
from ragguard.local_detector import LocalDetectorConfig, LocalPromptInjectionDetector

torch.set_num_threads(2)
model = LocalPromptInjectionDetector(LocalDetectorConfig(
    '90c9989b1a342275dd0d1a95aad283c04e075671',
    model_id='protectai/deberta-v3-base-prompt-injection-v2',
))
print(model.score('The service supports role-based access control.'))
PY
```

`score()` returns the injection-class softmax score and token count. It does not
make a policy decision. `detect()` requires an explicit calibration record matching
both the model ID and revision. Use `calibrate_threshold(..., model_id=...)` on a
separate labeled development set, then evaluate that fixed operating point on the
held-out split. A model score is not a guarantee of attack probability or safety.
See [detector integration](DETECTORS.md) for the calibration and process-wrapper
contracts, and the [evaluation guide](../evals/README.md) for available runners.

Both supported models have a 512-token adapter ceiling. The adapter refuses
oversized text rather than silently truncating it. Oversized and failed cases
must remain explicit in reports and must never be treated as successful clean
predictions. Do not quote classifier-only recall as end-to-end protection of a
long retrieved context that the classifier could not inspect.

## Measured smoke run and limits

A real offline CPU run on this machine used two PyTorch threads. Loading the
model and scoring the first 11-token benign sentence took 7.73 seconds. Ten warm
repetitions of that sentence averaged 29.6 ms. A 12-token instruction-override
sample took 37.4 ms. Scores were approximately `0.00000212` and `0.99999976`
respectively. These are two functional smoke inputs, not an accuracy benchmark,
and their short lengths do not represent 512-token latency.

Independent external corpus evaluation is reported separately by its runner;
corpus metrics must include the chosen split, calibration hash, scored/error
counts and final threshold. NotInject and InjecAgent are public data. Exact or
near-duplicate overlap with this model's training data cannot be ruled out from
its card, so external results are not proof of held-out generalization. The
corpora also measure text classification, not successful compromise of a live
agent or prevention of tool side effects. A paired model probe, if reported, is a
separate experiment with its own model, sample size and outcome definition.
