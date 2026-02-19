# NVIDIA Morpheus Integration Guide
## QUIC DoS Autoencoder — Real-Time Detection Pipeline

**Project:** QUIC Handshake Degradation Detection | **Student:** Safaa | **Context:** Nokia Research Internship  
**Morpheus Version:** 25.06 | **Date:** February 2026

> This is an architectural and methodological reference — not a tested implementation. It maps each component of the existing research pipeline to its Morpheus equivalent, giving a future implementer a technically grounded roadmap.

---

## 1. What Morpheus Is and Why It Fits

**NVIDIA Morpheus** is a GPU-accelerated cybersecurity pipeline framework built on four technologies: **RAPIDS (cuDF/cuML)** for GPU-resident DataFrame operations; **MRC (Morpheus Runtime Core)**, a graph-execution engine that manages typed stage DAGs, thread scheduling, and backpressure; **Triton Inference Server** for serving ONNX/TensorRT models via gRPC with dynamic batching; and **Kafka** for streaming telemetry ingestion (files can be used instead for research deployments).

A Morpheus pipeline is a sequence of **stages** — typed, composable units of work. Data flows as `MessageMeta` (raw DataFrames) or `ControlMessage` (DataFrame + tensor payload) objects between stages. MRC validates message types between adjacent stages at build time, before any data flows.

```
Zeek conn.log  ──►  Feature Computation  ──►  Triton          ──►  MSE Scoring  ──►  Alert
(file / Kafka)       + Scaling                 (autoencoder         + Threshold       file /
                     [custom stage]            forward pass)        Filtering         Kafka
```

**Why this model fits Morpheus well:** the autoencoder operates on 13 tabular flow-level features (`pipeline-fil` is designed for exactly this), outputs a per-flow reconstruction score mapping directly to Morpheus's `add-scores → filter` postprocessing pattern, requires no retraining on the live stream (train-once, infer-continuously), and the expected throughput (thousands of flows/min) is well within what a single T4/A100 handles.

**Pipeline mode:** `pipeline-fil` via the **Python API** (not the CLI), because the custom preprocessing logic — log transform, feature selection, RobustScaler — requires custom `SinglePortStage` subclasses that cannot be expressed as CLI arguments.

---

## 2. Prerequisites and Installation

**Hardware minimums:** NVIDIA T4 GPU (16 GB VRAM), CUDA 12.1, 32 GB RAM, 8 CPU cores, 50 GB storage. An A100 with 64 GB RAM is recommended for production throughput. CPU-only mode (`ExecutionMode.CPU`) is available for development but is significantly slower.

**Installation:** Use the pre-built NGC Docker containers — building from source requires resolving complex CUDA/MRC/RAPIDS interdependencies that are pre-resolved in the image. Steps: (1) authenticate with `nvcr.io` using a free NVIDIA developer account; (2) pull `nvcr.io/nvidia/morpheus/morpheus:25.06-runtime` and `nvcr.io/nvidia/tritonserver:24.10-py3`; (3) verify GPU access inside the container with `nvidia-smi`; (4) install three additional packages inside the Morpheus container: `tf2onnx`, `onnx`, and `joblib` (needed for model export and scaler loading — not included in the base image).

**Directory layout:**
```
quic-dos-morpheus/
├── models/triton-model-repo/quic_dos_autoencoder/
│   ├── config.pbtxt          ← Triton model configuration
│   └── 1/model.onnx          ← exported autoencoder
├── artifacts/
│   ├── robust_scaler.joblib  ← fitted RobustScaler (from notebook)
│   ├── feature_cols.json     ← ordered list of 13 final feature names
│   ├── log_transform_cols.json  ← 9 heavy-tail column names
│   └── threshold.json        ← anomaly threshold (95th percentile value)
├── stages/                   ← three custom stage files
├── pipeline.py               ← pipeline assembly script
└── docker-compose.yml        ← Triton + Morpheus orchestration
```

The `artifacts/` directory is the bridge between the notebook and the pipeline. Everything the preprocessing stage needs to replicate the notebook's behaviour exactly must be saved here at training time and loaded at pipeline startup.

---

## 3. Exporting the Model for Triton

Triton requires the autoencoder in **ONNX format** — not Keras `.h5` — so it can apply dynamic batching and GPU optimisation via its `onnxruntime` backend.

**Step 1 — Save artifacts from the notebook.** Before closing `DOS_Detection.ipynb`, save all four artifacts to `artifacts/`:

- `robust_scaler.joblib` — the fitted scaler, serialised with `joblib.dump()`. Must be the scaler fitted on the benign training set, not re-fitted anywhere else.
- `feature_cols.json` — `list(X_benign.columns)` after the correlation filtering step. The order matters: the scaler was fitted on this exact sequence.
- `log_transform_cols.json` — the `HEAVY_TAIL` list from the notebook (9 column names). Save it explicitly rather than hardcoding it in the pipeline.
- `threshold.json` — the result of `numpy.percentile(err_benign, 95)`, stored with the percentile value for traceability.

**Step 2 — Export to ONNX.** Use `tf2onnx` to convert the trained Keras model. Key requirements: declare a dynamic batch dimension (`[None, 13]` input shape); use ONNX opset 13 (well-supported by Triton); save to `models/triton-model-repo/quic_dos_autoencoder/1/model.onnx` (the `1/` subdirectory is Triton's mandatory version numbering). After export, note the exact input and output tensor names assigned by `tf2onnx` (e.g., `"input"`, `"output_0"`) — these must match exactly in both `config.pbtxt` and in the custom preprocessing stage.

**Step 3 — Validate.** Run `onnx.checker.check_model()` on the exported file, then use `onnxruntime` directly to send a dummy batch of shape `[N, 13]` through the model and confirm the output shape is `[N, 13]`. Do this before involving Triton — it isolates export problems from configuration problems.

**Step 4 — Write `config.pbtxt`.** This is a Protocol Buffer text file written manually. Required fields:

| Field | Value / Notes |
|-------|--------------|
| `name` | `"quic_dos_autoencoder"` — must match directory name exactly |
| `backend` | `"onnxruntime"` |
| `max_batch_size` | `1024` — should match or exceed `pipeline_batch_size` |
| Input tensor `name` | Must match the ONNX graph's input tensor name exactly |
| Input/output `data_type` | `TYPE_FP32` |
| Input/output `dims` | `[13]` — batch dimension is implicit when `max_batch_size > 0` |
| `dynamic_batching` | Enable; set `preferred_batch_size: [128, 256, 512, 1024]` and `max_queue_delay_microseconds: 5000` |
| `instance_group` | `kind: KIND_GPU`, `count: 1` for a single-GPU setup |

Full `config.pbtxt` reference: https://docs.nvidia.com/deeplearning/triton-inference-server/user-guide/docs/user_guide/model_configuration.html

---

## 4. Custom Pipeline Stages

Three custom stages are needed. All inherit from Morpheus base classes and must implement four methods: `name` (unique string identifier), `accepted_types` (tuple of upstream message types accepted), `compute_schema` (declares the output message type for build-time checking), and `_build_single` (attaches the stage's node to the MRC graph, typically via `ops.map(self.on_data)`). Artifacts are loaded once in `__init__` — never inside `on_data`.

### Stage 1: Zeek Flow Source (`SingleOutputSource`)

**Output:** `MessageMeta` (cuDF DataFrame with raw Zeek `conn.log` columns)

Supports two modes, selectable via a constructor argument. **Single-file mode** reads one `conn.log` file, emits flows in batches, and signals completion — use this for offline evaluation against the existing dataset. **Directory-watch mode** polls a directory for new rotated log files (named `conn.log.TIMESTAMP` by Zeek after each rotation), processes new files as they appear, and runs indefinitely — use this for near-real-time deployment.

Parsing details: skip lines beginning with `#` (Zeek headers); replace `-` with `0` in numeric fields before type conversion; convert all numeric columns (`orig_pkts`, `resp_pkts`, `orig_bytes`, `resp_bytes`, `duration`, etc.) to float. After parsing into pandas, convert to a **cuDF DataFrame** before constructing `MessageMeta` so all downstream stages use GPU-accelerated operations without an explicit conversion step.

### Stage 2: Preprocessing Stage (`SinglePortStage`)

**Input:** `MessageMeta` | **Output:** `ControlMessage` (payload + scaled tensor in `TensorMemory`)

This stage must replicate the notebook's preprocessing in exact order. Any deviation — wrong column order, missing log transform, scaling before log transform — corrupts reconstruction errors. The `on_data` method implements five steps:

1. **Feature computation.** Derive all 19 features from raw Zeek columns using the same formulas as `extract_features.py`: rate features (counts ÷ duration), ratio/asymmetry features (|FWD−REV|/TOTAL), bidirectionality proxy (`min(FWD_pkts, REV_pkts)`), mean packet sizes (bytes ÷ packets), timing (duration ÷ FWD packets). Floor duration at 0.001s; replace inf/NaN with 0. All operations have direct cuDF equivalents.

2. **Log transform.** Apply `log1p` to the columns listed in the loaded `log_transform_cols.json`. Use the artifact file — do not hardcode the column list.

3. **Feature selection.** Select only the 13 columns listed in `feature_cols.json`, in that exact order. This implicitly drops the 6 correlated features removed during training.

4. **Scaling.** The RobustScaler is a scikit-learn object (CPU-only). The stage must: convert cuDF → pandas → NumPy float32, call `scaler.transform()`, then move the result back to GPU with `cupy.asarray()`. This CPU round-trip is acceptable at research scale; see Section 7 for the production mitigation.

5. **Pack into ControlMessage.** Create a `ControlMessage`, attach the original `MessageMeta` as payload (to preserve raw flow metadata for the output), and attach a `TensorMemory` with the scaled tensor keyed under the **exact same name as Triton's input tensor** (as declared in `config.pbtxt`). `TritonInferenceStage` maps tensor keys to Triton inputs by name.

### Stage 3: Reconstruction Error Stage (`SinglePortStage`)

**Input:** `ControlMessage` (after Triton inference) | **Output:** `ControlMessage` (same, with new columns)

After `TritonInferenceStage`, the `ControlMessage`'s `TensorMemory` contains two CuPy arrays of shape `[N, 13]`: the original scaled input and Triton's reconstruction output (keyed under the ONNX output tensor name). This stage computes per-flow MSE as the mean squared difference between those two arrays over the 13 feature dimensions, producing a 1D array of shape `[N]`. It then compares each MSE against the threshold loaded from `threshold.json` to produce a boolean anomaly flag. Both `reconstruction_error` (float32) and `is_anomaly` (bool) are appended to the payload DataFrame via `mutable_dataframe()`. Optionally append `anomaly_threshold` as a constant column for traceability.

---

## 5. Assembling the Pipeline

### Data Flow

```
ZeekFlowSourceStage        [custom]   → MessageMeta (raw Zeek columns, cuDF)
DeserializeStage           [built-in] → partitions into batch chunks; MessageMeta → ControlMessage
QuicDoSPreprocessStage     [custom]   → feature computation + scaling → ControlMessage + TensorMemory
MonitorStage               [built-in] → logs preprocessing throughput (optional)
TritonInferenceStage       [built-in] → sends tensor to Triton; appends reconstruction to TensorMemory
MonitorStage               [built-in] → logs inference throughput (optional)
ReconstructionErrorStage   [custom]   → computes MSE; appends reconstruction_error, is_anomaly
FilterDetectionsStage      [built-in] → passes only is_anomaly == True flows downstream
SerializeStage             [built-in] → ControlMessage → MessageMeta / JSON records
WriteToFileStage           [built-in] → alerts.jsonl  (or WriteToKafkaStage for streaming)
```

### Key Configuration (`Config` object)

| Parameter | Value | Notes |
|-----------|-------|-------|
| `mode` | `PipelineModes.FIL` | Tabular numerical pipeline mode |
| `num_threads` | 8 | CPU preprocessing threads |
| `pipeline_batch_size` | 1024 | Flows per batch |
| `model_max_batch_size` | 1024 | Must match `max_batch_size` in `config.pbtxt` |
| `feature_length` | 13 | Scaled tensor width |

### Ordering Constraints

MRC enforces type compatibility at build time. The critical ordering rules are: `DeserializeStage` must immediately follow the source (it converts `MessageMeta → ControlMessage`); `ReconstructionErrorStage` must immediately follow `TritonInferenceStage` (both input and output tensors must still be in `TensorMemory`); `FilterDetectionsStage` must follow `ReconstructionErrorStage` (it filters on `is_anomaly`, which doesn't exist before that stage); `SerializeStage` must precede any file/Kafka sink (sinks expect `MessageMeta`, not `ControlMessage`).

### Deployment

Use Docker Compose with two services (`triton` and `morpheus`). Morpheus must not start until Triton reports the model is ready — use `depends_on` with a healthcheck on Triton's REST health endpoint (`GET /v2/health/ready`, port 8000). Both containers share the GPU via the NVIDIA container runtime and both need volume mounts for `models/triton-model-repo/` and `artifacts/`.

---

## 6. Running and Monitoring

**Pre-flight checks (in order):**
1. Validate the ONNX model with `onnxruntime` using a dummy `[N, 13]` input — confirm output shape is `[N, 13]`. Do this before involving Triton to isolate export issues.
2. Confirm Triton loaded the model: `GET http://localhost:8000/v2/models/quic_dos_autoencoder/ready` should return `state: READY`.
3. Load and print each artifact (`feature_cols.json` should have exactly 13 names, threshold should be a plausible positive float, scaler should load without error).

**Throughput monitoring:** Place `MonitorStage` after preprocessing and after inference. If preprocessing is the bottleneck, increase `num_threads` or replace the sklearn scaler round-trip with cuML. If inference is the bottleneck, increase Triton's `instance_group count` or enable TensorRT optimisation in `config.pbtxt`.

**Output validation:** Run the pipeline against the existing labelled datasets. Against `normal_flows.csv` (159,420 flows), expect ~5% flagged (the operating FPR). Against `malicious_flows.csv` (14,375 flows), expect ~100% flagged (consistent with AUC 0.9998 and 100% malicious SF detection from training). Significant divergence indicates a preprocessing mismatch — most likely a missing log transform, wrong column order, or scaler mismatch.

**Drift monitoring:** Add Morpheus's `mlflow-drift` stage after `ReconstructionErrorStage` to track the mean and 95th percentile of `reconstruction_error` over time. A sustained upward trend on known-benign traffic is the signal to recalibrate the threshold. Run MLflow as a third Docker Compose service.

---

## 7. Limitations and Production Considerations

**Fixed threshold.** The 95th percentile threshold is computed once from the benign validation set. As normal QUIC traffic patterns drift over time (client software updates, usage changes), the false positive rate will rise without recalibration. Mitigation: collect a window of confirmed-benign traffic periodically, compute reconstruction errors with the existing model, update `threshold.json` to the new 95th percentile. The MLflow drift monitor provides the early-warning signal.

**Detection latency.** In directory-watch mode, Zeek rotates logs every hour by default — introducing up to one hour of detection latency. Configuring Zeek to rotate every 60 seconds (`LogRotationInterval` in `local.zeek`) reduces this to under a minute. For a Nokia production deployment, the recommended path is the **Zeek Kafka plugin**, which streams `conn.log` events to a Kafka topic in real time as each connection closes; the custom source stage is then replaced by Morpheus's built-in `KafkaSourceStage`, reducing latency to seconds.

**No temporal or per-source context.** Each flow is scored independently. A slow-rate attacker staying below the per-flow statistical threshold would not be detected. The extension is a rolling window aggregation stage that groups flows by source IP over a sliding time window before scoring — Morpheus's `DFPRollingWindowStage` (from the Digital Fingerprinting pipeline) implements exactly this pattern.

**Training coverage.** The model was trained on traffic between two specific machines using a minimal aioquic server. A production deployment would expose it to different RTT characteristics, diverse QUIC client implementations, and richer HTTP/3 traffic patterns. The model should be retrained on traffic from the target environment before production use. The pipeline infrastructure remains unchanged — only the model artifact and threshold need replacing.

**Scaler CPU round-trip.** The RobustScaler requires moving data from GPU to CPU and back (sklearn is CPU-only). At research scale this is fine; at very high flow rates it becomes a bottleneck. Mitigation: reimplement scaling using cuML to keep data on GPU throughout the preprocessing stage.

---
