"""FastAPI application.

Run:  uvicorn app.main:app --port 8000
Then open http://localhost:8000          (the CYBER ATTACK DETECTION SYSTEM dashboard, once the frontend is built)
          http://localhost:8000/docs     (interactive API docs)
"""
import asyncio
import tempfile
import time
from contextlib import asynccontextmanager
from pathlib import Path

import pandas as pd
from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import config
from app.capture import flows_from_pcap
from app.capture.sources import list_interfaces
from app.events import EventStore
from app.live import Engine, Hub
from app.model_service import MissingFeaturesError, ModelService
from app.schemas import BatchRequest, BatchResponse, Flow, Prediction

CSV_CHUNK = 20_000  # rows scored at a time, keeps memory flat for big CSVs
API_PREFIXES = ("live", "predict", "events", "stats", "sample", "model", "health", "docs", "openapi")


class SourceRequest(BaseModel):
    mode: str = "auto"  # auto | live | pcap | demo
    iface: str | None = None


def create_app(artifact_dir: Path | None = None, autostart: bool | None = None) -> FastAPI:
    """App factory: tests pass a temporary artifact folder, production uses the default."""
    folder = Path(artifact_dir) if artifact_dir else config.ARTIFACT_DIR
    autostart = config.AUTOSTART if autostart is None else autostart

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Loaded ONCE at startup, never per request (loading a model per request would be very slow).
        app.state.service = ModelService(folder)
        app.state.events = EventStore(config.RECENT_EVENTS_MAX)
        app.state.hub = Hub()
        app.state.hub.attach(asyncio.get_running_loop())
        app.state.engine = Engine(app.state.service, app.state.events, app.state.hub)
        if autostart:  # "just open it": capture starts by itself
            await asyncio.to_thread(app.state.engine.start, config.SOURCE)
        yield
        app.state.engine.stop()

    app = FastAPI(title="CYBER ATTACK DETECTION SYSTEM API", version="2.0.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.CORS_ORIGINS,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(MissingFeaturesError)
    async def missing_features_handler(_: Request, exc: MissingFeaturesError):
        return JSONResponse(
            status_code=422,
            content={"detail": "Missing required features.", "missing_features": exc.missing},
        )

    def service(request: Request) -> ModelService:
        return request.app.state.service

    def events(request: Request) -> EventStore:
        return request.app.state.events

    def engine(request: Request) -> Engine:
        return request.app.state.engine

    # ------------------------------------------------------------------ info
    @app.get("/health")
    def health(svc: ModelService = Depends(service)):
        return {"status": "ok", "model": svc.model_type, "n_features": len(svc.features)}

    @app.get("/model/info")
    def model_info(svc: ModelService = Depends(service)):
        return {
            "model": svc.model_type,
            "classes": svc.classes,
            "features": svc.features,  # exact names the API expects, in training order
            "metadata": svc.metadata,  # training date, test metrics, versions (if metadata.json exists)
        }

    # ------------------------------------------------------------------ prediction
    @app.post("/predict", response_model=Prediction)
    def predict_one(flow: Flow, svc: ModelService = Depends(service), store: EventStore = Depends(events)):
        df = pd.DataFrame([flow.features])
        result = svc.predict(df, [flow.meta])
        store.add(result)
        return result[0]

    @app.post("/predict/batch", response_model=BatchResponse)
    def predict_batch(body: BatchRequest, svc: ModelService = Depends(service), store: EventStore = Depends(events)):
        t0 = time.perf_counter()
        df = pd.DataFrame([f.features for f in body.flows])
        result = svc.predict(df, [f.meta for f in body.flows])
        store.add(result)
        return {
            "count": len(result),
            "attacks": sum(r["is_attack"] for r in result),
            "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
            "predictions": result,
        }

    @app.post("/predict/csv")
    def predict_csv(
        file: UploadFile = File(..., description="CSV with the model's feature columns (CICIDS day files work as-is)."),
        return_predictions: bool = Query(False, description="Include every row's prediction (use for small files)."),
        max_rows: int = Query(config.MAX_CSV_ROWS, ge=1, le=config.MAX_CSV_ROWS),
        svc: ModelService = Depends(service),
        store: EventStore = Depends(events),
    ):
        t0 = time.perf_counter()
        try:
            df = pd.read_csv(file.file, nrows=max_rows, encoding_errors="replace", low_memory=False)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Could not read CSV: {exc}")
        df.columns = df.columns.str.strip()

        all_results: list[dict] = []
        for start in range(0, len(df), CSV_CHUNK):
            chunk = df.iloc[start : start + CSV_CHUNK]
            meta = [{"row": int(i)} for i in chunk.index]
            part = svc.predict(chunk, meta)
            store.add(part)
            all_results.extend(part)

        labels = [r["label"] for r in all_results]
        counts = pd.Series(labels).value_counts().to_dict()
        body = {
            "rows": len(all_results),
            "attacks": sum(r["is_attack"] for r in all_results),
            "predicted_counts": counts,
            "rows_with_filled_values": sum(r["imputed_values"] > 0 for r in all_results),
            "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
            # Only when the file has a Label column (e.g. a labelled test/CICIDS file).
            "evaluation": svc.evaluate(df["Label"], labels) if "Label" in df.columns else None,
        }
        if return_predictions:
            body["predictions"] = all_results
        return body

    # ------------------------------------------------------------------ dashboard helpers
    @app.get("/events/recent")
    def recent_events(
        limit: int = Query(50, ge=1, le=config.RECENT_EVENTS_MAX),
        only_attacks: bool = False,
        store: EventStore = Depends(events),
    ):
        return {"events": store.recent(limit, only_attacks)}

    @app.get("/stats")
    def stats(store: EventStore = Depends(events)):
        return store.stats()

    @app.get("/sample")
    def sample(
        label: str | None = Query(None, description="e.g. DDoS, PortScan, BENIGN"),
        n: int = Query(1, ge=1, le=100),
        svc: ModelService = Depends(service),
    ):
        """Random held-out test flows, ready to POST to /predict/batch (handy for demos and the UI)."""
        try:
            flows = svc.sample_flows(label, n)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        if not flows:
            raise HTTPException(status_code=404, detail=f"No test rows with label '{label}'.")
        return {"flows": flows}

    # ------------------------------------------------------------------ live monitoring
    @app.get("/live/status")
    def live_status(eng: Engine = Depends(engine)):
        return eng.status()

    @app.get("/live/snapshot")
    def live_snapshot(eng: Engine = Depends(engine)):
        return eng.snapshot()

    @app.get("/live/interfaces")
    def live_interfaces():
        try:
            return {"interfaces": list_interfaces(), "error": None}
        except Exception as exc:  # scapy missing, or no capture driver
            return {"interfaces": [], "error": str(exc)}

    @app.post("/live/source")
    def live_source(body: SourceRequest, eng: Engine = Depends(engine)):
        """Switch what the monitor watches: your network (live), a capture file (pcap) or demo flows."""
        if body.mode not in ("auto", "live", "pcap", "demo"):
            raise HTTPException(status_code=400, detail="mode must be auto, live, pcap or demo")
        return eng.start(body.mode, body.iface)

    @app.websocket("/live/ws")
    async def live_ws(ws: WebSocket):
        await ws.accept()
        hub: Hub = ws.app.state.hub
        q = hub.subscribe()
        reader = asyncio.create_task(_drain_incoming(ws))  # notices when the browser disconnects
        try:
            await ws.send_json({"type": "snapshot", **ws.app.state.engine.snapshot()})
            while True:
                getter = asyncio.create_task(q.get())
                done, _ = await asyncio.wait({getter, reader}, return_when=asyncio.FIRST_COMPLETED)
                if reader in done:
                    getter.cancel()
                    break
                await ws.send_json(getter.result())
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            hub.unsubscribe(q)
            reader.cancel()

    @app.post("/live/analyze-pcap")
    def analyze_pcap(file: UploadFile = File(...), svc: ModelService = Depends(service)):
        """Upload a Wireshark capture (.pcap / .pcapng): flows are rebuilt and every one is classified."""
        t0 = time.perf_counter()
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename or "x.pcap").suffix) as tmp:
            size = 0
            while chunk := file.file.read(1 << 20):
                size += len(chunk)
                if size > config.MAX_UPLOAD_PCAP_MB * 1_000_000:
                    Path(tmp.name).unlink(missing_ok=True)
                    raise HTTPException(status_code=413, detail=f"Capture is larger than {config.MAX_UPLOAD_PCAP_MB} MB.")
                tmp.write(chunk)
        try:
            flows, capture = flows_from_pcap(tmp.name, config.MAX_UPLOAD_PCAP_PACKETS)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Could not read this capture: {exc}")
        finally:
            Path(tmp.name).unlink(missing_ok=True)

        preds: list[dict] = []
        if flows:
            df = pd.DataFrame([f.features() for f in flows])
            preds = svc.predict(df, [f.meta() for f in flows])
        attacks = sorted((p for p in preds if p["is_attack"]), key=lambda p: -p["confidence"])
        benign = [p for p in preds if not p["is_attack"]]
        return {
            "filename": file.filename,
            "capture": capture,
            "flows": len(preds),
            "attacks": len(attacks),
            "predicted_counts": pd.Series([p["label"] for p in preds]).value_counts().to_dict() if preds else {},
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
            "preview": attacks[:200] + benign[:100],
        }

    # ------------------------------------------------------------------ the built React app
    index = config.STATIC_DIR / "index.html"
    if index.exists():
        app.mount("/assets", StaticFiles(directory=config.STATIC_DIR / "assets"), name="assets")

        @app.get("/", include_in_schema=False)
        def root():
            return FileResponse(index)

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            if path.split("/")[0] in API_PREFIXES:
                raise HTTPException(status_code=404)
            candidate = (config.STATIC_DIR / path).resolve()
            if candidate.is_file() and config.STATIC_DIR.resolve() in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(index)  # client-side routes like /monitor
    else:

        @app.get("/", include_in_schema=False)
        def root():
            return RedirectResponse(url="/docs")  # no frontend build yet: the bare address opens the API docs

    return app


async def _drain_incoming(ws: WebSocket) -> None:
    try:
        while True:
            await ws.receive_text()
    except Exception:
        return


app = create_app()
