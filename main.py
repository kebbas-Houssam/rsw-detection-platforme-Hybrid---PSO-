"""
main.py - Ransomware Detection Platform (debuggable)
نسخة مصغّرة/محدثة من ملفك مع إضافات logging تشخيصيّة و endpoint تصحيحي.
"""

import os
import sys
import time
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Any, Dict
from collections import deque, defaultdict

import numpy as np

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import uvicorn

# ML placeholders (imports but if models not exist we degrade gracefully)
import joblib
import tensorflow as tf
from tensorflow.keras.models import load_model
from sklearn.preprocessing import RobustScaler
import xgboost as xgb

# -------------------- Logging --------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("ransomware_detection.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("ransomware_detection")
logger.setLevel(logging.DEBUG)  # enable debug logs for development

# -------------------- Pydantic models --------------------
class IOTraceData(BaseModel):
    timestamp: float = Field(...)
    operation_type: str = Field(...)
    file_path: str = Field(...)
    offset: int = Field(...)
    size: int = Field(...)
    process_id: int = Field(...)
    process_name: str = Field(...)

class DetectionResult(BaseModel):
    timestamp: str
    process_name: str
    process_id: int
    file_path: str
    primary_prediction: float
    hybrid_prediction: float
    risk_level: str
    confidence: float
    features: dict
    alert_triggered: bool

class SystemStatus(BaseModel):
    status: str
    uptime: float
    total_predictions: int
    alerts_triggered: int
    current_load: dict
    model_info: dict
    last_update: str

# -------------------- Detection Engine --------------------
class RansomwareDetectionEngine:
    def __init__(self, model_path: str = "./models", sequence_length: int = 50):
        self.model_path = model_path
        self.sequence_length = sequence_length
        self.feature_columns = [
            'read_write_ratio','war_ratio','wss','entropy',
            'read_pct','write_pct','repeat_ratio',
            'read_entropy','write_entropy','total_ops',
            'write_to_unique_ratio','avg_offset_gap','burstiness'
        ]
        self.io_buffer = defaultdict(deque)
        self.buffer_max_size = 5000
        self.last_prediction_time = defaultdict(float)
        self.primary_model = None
        self.xgb_model = None
        self.scaler = None
        self.xgb_scaler = None

        self.alert_threshold = 0.24
        self.primary_threshold = 0.5
        self.hybrid_threshold = 0.5

        self.total_predictions = 0
        self.alerts_triggered = 0
        self.start_time = time.time()
        self.recent_alerts = deque(maxlen=200)

        self.load_models()
        logger.info("Engine initialized")

    def load_models(self):
        try:
            primary_path = os.path.join(self.model_path, "best_pso_ransomware_model.h5")
            if os.path.exists(primary_path):
                self.primary_model = load_model(primary_path, compile=False)
                logger.info(f"Primary model loaded: {primary_path}")
            else:
                logger.warning("Primary model not found: running in demo mode")

            xgb_files = [f for f in os.listdir(self.model_path) if f.startswith("pso_ransomware_model_xgboost_") and f.endswith(".pkl")]
            if xgb_files:
                xgb_file = sorted(xgb_files)[-1]
                self.xgb_model = joblib.load(os.path.join(self.model_path, xgb_file))
                logger.info(f"XGBoost loaded: {xgb_file}")
            else:
                logger.warning("XGBoost not found: hybrid stage disabled")

            scaler_files = [f for f in os.listdir(self.model_path) if f.startswith("pso_ransomware_model_scaler_") and f.endswith(".pkl")]
            if scaler_files:
                self.scaler = joblib.load(os.path.join(self.model_path, sorted(scaler_files)[-1]))
                logger.info("Scaler loaded")
            else:
                logger.info("No scaler found: skipping scaling")

        except Exception as e:
            logger.exception(f"Error loading models: {e}")

    def _calculate_entropy(self, values):
        if not values:
            return 0.0
        vals, counts = np.unique(values, return_counts=True)
        probs = counts / counts.sum()
        return float(-np.sum(probs * np.log2(probs + 1e-10)))

    def extract_features_from_traces(self, traces: List[IOTraceData]) -> Dict[str, float]:
        if not traces:
            return {c:0.0 for c in self.feature_columns}
        try:
            ops = [t.operation_type for t in traces]
            offsets = [t.offset for t in traces]
            sizes = [t.size for t in traces]
            total_ops = len(traces)
            read_ops = sum(1 for o in ops if o == 'read')
            write_ops = sum(1 for o in ops if o == 'write')
            features = {}
            features['read_write_ratio'] = read_ops / max(write_ops,1)
            features['read_pct'] = read_ops / total_ops
            features['write_pct'] = write_ops / total_ops
            features['total_ops'] = total_ops
            features['wss'] = len(set(offsets))
            features['war_ratio'] = write_ops / max(read_ops + write_ops,1)
            cnts = {}
            for off in offsets:
                cnts[off] = cnts.get(off,0)+1
            repeated = sum(1 for v in cnts.values() if v>1)
            features['repeat_ratio'] = repeated / max(total_ops,1)
            offset_probs = np.array(list(cnts.values())) / total_ops
            features['entropy'] = float(-np.sum(offset_probs * np.log2(offset_probs + 1e-10)))
            read_offsets = [offsets[i] for i,o in enumerate(ops) if o=='read']
            write_offsets = [offsets[i] for i,o in enumerate(ops) if o=='write']
            features['read_entropy'] = self._calculate_entropy(read_offsets)
            features['write_entropy'] = self._calculate_entropy(write_offsets)
            unique_write_offsets = len(set(write_offsets)) if write_offsets else 1
            features['write_to_unique_ratio'] = write_ops / max(unique_write_offsets,1)
            sorted_offsets = sorted(offsets)
            if len(sorted_offsets) > 1:
                gaps = [sorted_offsets[i+1]-sorted_offsets[i] for i in range(len(sorted_offsets)-1)]
                features['avg_offset_gap'] = float(np.mean(gaps)) if gaps else 0.0
            else:
                features['avg_offset_gap'] = 0.0
            if len(traces) > 1:
                t_sorted = sorted([t.timestamp for t in traces])
                diffs = np.diff(t_sorted)
                features['burstiness'] = float(np.std(diffs)/ (np.mean(diffs)+1e-9))
            else:
                features['burstiness'] = 0.0
            # fill missing
            for c in self.feature_columns:
                features.setdefault(c, 0.0)
            # clean nan/inf
            for k,v in features.items():
                if np.isnan(v) or np.isinf(v):
                    features[k] = 0.0
            return features
        except Exception as e:
            logger.exception(f"extract_features error: {e}")
            return {c:0.0 for c in self.feature_columns}

    def add_io_trace(self, trace: IOTraceData):
        key = f"{trace.process_name}_{trace.process_id}"
        self.io_buffer[key].append(trace)
        if len(self.io_buffer[key]) > self.buffer_max_size:
            self.io_buffer[key].popleft()
        # decide to predict
        if len(self.io_buffer[key]) >= max(10, self.sequence_length // 5):
            now = time.time()
            if now - self.last_prediction_time[key] > 0.5:
                self.last_prediction_time[key] = now
                return True
        return False

    def create_sequence(self, process_key: str):
        if process_key not in self.io_buffer:
            return None
        traces = list(self.io_buffer[process_key])
        if len(traces) < self.sequence_length:
            return None
        recent = traces[-self.sequence_length:]
        seq = []
        window_size = max(3, len(recent)//self.sequence_length)
        for i in range(self.sequence_length):
            s = int(i * len(recent) / self.sequence_length)
            e = min(s + window_size, len(recent))
            window = recent[s:e] if e>s else recent[-3:]
            feats = self.extract_features_from_traces(window)
            vec = [feats[c] for c in self.feature_columns]
            seq.append(vec)
        return np.array([seq], dtype=np.float32)

    async def predict_ransomware(self, process_key: str) -> Optional[DetectionResult]:
        try:
            seq = self.create_sequence(process_key)
            if seq is None:
                logger.debug(f"[DEBUG] No sequence for {process_key}; buffer_len={len(self.io_buffer.get(process_key,[]))}")
                return None

            # diagnostic: raw sequence stats
            try:
                logger.info(f"[DEBUG] sequence.shape for {process_key}: {seq.shape}")
                logger.info(f"[DEBUG] seq raw min/max: {float(np.min(seq)):.6f} / {float(np.max(seq)):.6f}")
            except Exception as e:
                logger.error(f"[DEBUG] error measuring seq: {e}")

            # scaling if present
            if self.scaler:
                try:
                    orig_shape = seq.shape
                    seq_rs = seq.reshape(-1, seq.shape[-1])
                    seq_scaled_rs = self.scaler.transform(seq_rs)
                    seq = seq_scaled_rs.reshape(orig_shape)
                    logger.info(f"[DEBUG] seq scaled min/max: {float(np.min(seq)):.6f} / {float(np.max(seq)):.6f}")
                except Exception as e:
                    logger.exception(f"[DEBUG] scaler transform failed: {e}")

            # primary prediction
            if not self.primary_model:
                # demo fallback
                primary_pred = float(np.random.random() * 0.3)
                hybrid_pred = primary_pred + float(np.random.random() * 0.2)
                logger.info(f"[DEBUG] Demo prediction primary={primary_pred:.6f} hybrid={hybrid_pred:.6f}")
            else:
                try:
                    primary_out = self.primary_model.predict(seq, verbose=0)
                    primary_pred = float(primary_out[0,0])
                except Exception as e:
                    logger.exception(f"Primary model predict failed: {e}")
                    primary_pred = 0.0

                hybrid_pred = primary_pred
                # hybrid stage
                if self.xgb_model:
                    try:
                        hybrid_features = self._extract_hybrid_features(seq, np.array([[primary_pred]]))
                        if self.xgb_scaler:
                            hf = self.xgb_scaler.transform(hybrid_features)
                        else:
                            hf = hybrid_features
                        proba = self.xgb_model.predict_proba(hf)
                        hybrid_pred = float(proba[0,1]) if proba.shape[1] > 1 else float(proba[0,0])
                    except Exception as e:
                        logger.exception(f"XGB predict_proba failed: {e}")

            risk = self._determine_risk_level(hybrid_pred)

            # last trace info
            last_trace = self.io_buffer[process_key][-1] if self.io_buffer[process_key] else None
            pname = last_trace.process_name if last_trace else process_key.split('_')[0]
            pid = last_trace.process_id if last_trace else int(process_key.split('_')[1]) if '_' in process_key else 0
            fpath = last_trace.file_path if last_trace else "unknown"

            features = self.extract_features_from_traces(list(self.io_buffer[process_key])[-10:])

            result = DetectionResult(
                timestamp=datetime.now().isoformat(),
                process_name=pname,
                process_id=pid,
                file_path=fpath,
                primary_prediction=primary_pred,
                hybrid_prediction=hybrid_pred,
                risk_level=risk,
                confidence=float(abs(hybrid_pred - 0.5) * 2),
                features=features,
                alert_triggered=hybrid_pred > self.alert_threshold
            )

            self.total_predictions += 1
            if result.alert_triggered:
                self.alerts_triggered += 1
                self.recent_alerts.append(result)
                logger.warning(f"RANSOMWARE ALERT: {pname} PID={pid} score={hybrid_pred:.6f} risk={risk}")

            logger.info(f"[PRED] {process_key} primary={primary_pred:.6f} hybrid={hybrid_pred:.6f} risk={risk}")
            return result

        except Exception as e:
            logger.exception(f"predict_ransomware error for {process_key}: {e}")
            return None

    def _extract_hybrid_features(self, sequence: np.ndarray, primary_pred_proba: np.ndarray):
        # create some simple stats as hybrid features
        try:
            pf = [float(primary_pred_proba[0,0]), int(primary_pred_proba[0,0] > 0.5)]
            seq_stats = []
            for fi in range(sequence.shape[-1]):
                vals = sequence[0,:,fi]
                seq_stats += [float(np.mean(vals)), float(np.std(vals)), float(np.min(vals)), float(np.max(vals)), float(np.median(vals))]
            seq_stats += [float(np.mean(sequence)), float(np.std(sequence)), float(np.var(sequence))]
            return np.array([pf + seq_stats])
        except Exception as e:
            logger.exception(f"_extract_hybrid_features error: {e}")
            return np.array([[float(primary_pred_proba[0,0]), 0.0]])

    def _determine_risk_level(self, score: float) -> str:
        if score >= 0.8:
            return "CRITICAL"
        if score >= 0.6:
            return "HIGH"
        if score >= 0.4:
            return "MEDIUM"
        if score >= 0.2:
            return "LOW"
        return "MINIMAL"

    def get_status(self) -> dict:
        uptime = time.time() - self.start_time
        current_load = {
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "active_processes": len(self.io_buffer),
            "buffer_size": sum(len(v) for v in self.io_buffer.values())
        }
        model_info = {
            "primary_model_loaded": self.primary_model is not None,
            "xgb_model_loaded": self.xgb_model is not None,
            "scaler_loaded": self.scaler is not None,
            "sequence_length": self.sequence_length,
            "feature_count": len(self.feature_columns),
            "alert_threshold": self.alert_threshold
        }
        return {
            "status": "running",
            "uptime": uptime,
            "total_predictions": self.total_predictions,
            "alerts_triggered": self.alerts_triggered,
            "current_load": current_load,
            "model_info": model_info,
            "last_update": datetime.now().isoformat()
        }

    def generate_test_alert(self):
        import random
        name = "test_alert.exe"
        pid = random.randint(1000,9999)
        result = DetectionResult(
            timestamp=datetime.now().isoformat(),
            process_name=name,
            process_id=pid,
            file_path="C:\\test\\alert.bin",
            primary_prediction=0.8,
            hybrid_prediction=0.9,
            risk_level="CRITICAL",
            confidence=0.8,
            features={c:0.5 for c in self.feature_columns},
            alert_triggered=True
        )
        self.alerts_triggered += 1
        self.recent_alerts.append(result)
        return result

# -------------------- App / Websocket manager --------------------
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
static_dir = Path(".")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

detection_engine = RansomwareDetectionEngine(model_path="./models", sequence_length=50)

class ConnectionManager:
    def __init__(self):
        self.active = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        logger.info(f"WS connected: total={len(self.active)}")

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict):
        bad=[]
        for c in list(self.active):
            try:
                await c.send_json(message)
            except Exception as e:
                bad.append(c)
                logger.error(f"Broadcast error: {e}")
        for b in bad:
            self.disconnect(b)

manager = ConnectionManager()

@app.get("/")
async def root():
    p = Path("dashboard.html")
    if p.exists():
        return FileResponse(str(p), media_type="text/html")
    return {"msg":"Place dashboard.html in working dir."}

@app.get("/status")
async def status():
    if not detection_engine:
        raise HTTPException(status_code=503, detail="not init")
    return detection_engine.get_status()

@app.post("/predict")
async def predict_one(trace: IOTraceData):
    if not detection_engine:
        raise HTTPException(status_code=503, detail="not init")
    should = detection_engine.add_io_trace(trace)
    if should:
        key = f"{trace.process_name}_{trace.process_id}"
        res = await detection_engine.predict_ransomware(key)
        if res:
            await manager.broadcast({"type":"prediction","data": res.dict()})
            return res
    raise HTTPException(status_code=202, detail="Trace added, insufficient data for prediction")

@app.post("/traces/batch")
async def traces_batch(traces: List[IOTraceData]):
    if not detection_engine:
        raise HTTPException(status_code=503, detail="not init")
    preds=[]
    for t in traces:
        should = detection_engine.add_io_trace(t)
        if should:
            key = f"{t.process_name}_{t.process_id}"
            r = await detection_engine.predict_ransomware(key)
            if r:
                preds.append(r)
                await manager.broadcast({"type":"prediction","data": r.dict()})
    return {"traces_processed": len(traces), "predictions_made": len(preds), "predictions":[p.dict() for p in preds]}

@app.post("/test/alert")
async def test_alert():
    if not detection_engine:
        raise HTTPException(status_code=503, detail="no engine")
    res = detection_engine.generate_test_alert()
    await manager.broadcast({"type":"alert","data": res.dict()})
    return res

@app.get("/alerts")
async def get_alerts(limit: int = 50):
    if not detection_engine:
        raise HTTPException(status_code=503, detail="no engine")
    recent = list(detection_engine.recent_alerts)[-limit:]
    return {"total_alerts": detection_engine.alerts_triggered, "recent_alerts":[r.dict() for r in recent]}

@app.post("/configure")
async def configure(cfg: dict):
    if not detection_engine:
        raise HTTPException(status_code=503, detail="no engine")
    if "alert_threshold" in cfg:
        val = float(cfg["alert_threshold"])
        detection_engine.alert_threshold = val
        logger.info(f"Alert threshold set to {val}")
    return {"message":"ok", "alert_threshold": detection_engine.alert_threshold}

@app.websocket("/stream")
async def stream(ws: WebSocket):
    await manager.connect(ws)
    try:
        # send status immediately
        await ws.send_json({"type":"status","data": detection_engine.get_status()})
        while True:
            msg = await ws.receive_json()
            # accept trace via WS
            if msg.get("type") == "trace" and msg.get("data"):
                try:
                    trace = IOTraceData(**msg["data"])
                    should = detection_engine.add_io_trace(trace)
                    if should:
                        key = f"{trace.process_name}_{trace.process_id}"
                        res = await detection_engine.predict_ransomware(key)
                        if res:
                            await manager.broadcast({"type":"prediction","data":res.dict()})
                except Exception as e:
                    logger.error(f"ws trace error: {e}")
            elif msg.get("type") == "get_status":
                await ws.send_json({"type":"status","data": detection_engine.get_status()})
    except WebSocketDisconnect:
        manager.disconnect(ws)
    except Exception as e:
        logger.exception(f"Websocket error: {e}")
        manager.disconnect(ws)

# ---- DEBUG force predict endpoint ----
@app.get("/debug/force_predict/{process_name}/{pid}")
async def debug_force_predict(process_name: str, pid: int):
    if not detection_engine:
        raise HTTPException(status_code=503, detail="no engine")
    key = f"{process_name}_{pid}"
    seq = detection_engine.create_sequence(key)
    buffer_len = len(detection_engine.io_buffer.get(key, []))
    if seq is None:
        return {"ok": False, "msg": "no sequence", "buffer_len": buffer_len}
    res = await detection_engine.predict_ransomware(key)
    if res:
        return {"ok": True, "primary": res.primary_prediction, "hybrid": res.hybrid_prediction, "risk": res.risk_level, "buffer_len": buffer_len}
    return {"ok": False, "msg": "prediction_failed", "buffer_len": buffer_len}

# -------------------- Run --------------------
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
