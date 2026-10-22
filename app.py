import json
import logging
import os
import sqlite3
import threading

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import engine

log = logging.getLogger("ga5")
logging.basicConfig(level=logging.INFO)


def log_config():
    for name in ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL", "DB_PATH"):
        value = os.environ.get(name)
        if value is None:
            log.info("env %s: MISSING", name)
        elif name == "LLM_API_KEY":
            log.info("env %s: set (length %d)", name, len(value))
        else:
            log.info("env %s: set, value=%r", name, value)


log_config()

DB_PATH = os.environ.get("DB_PATH", "incidents.db")
LOCK = threading.Lock()
DB = sqlite3.connect(DB_PATH, check_same_thread=False)
DB.execute("CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, req_hash TEXT NOT NULL, state TEXT NOT NULL)")
DB.execute("CREATE TABLE IF NOT EXISTS receipts (receipt_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, req_hash TEXT NOT NULL, response TEXT NOT NULL)")
DB.commit()

app = FastAPI()


def fail(status, message):
    # Never echo request bodies, so sensitive input cannot leak in errors.
    return JSONResponse({"error": message}, status_code=status)


async def read_json(request):
    try:
        return await request.json()
    except Exception:
        return None


@app.post("/v2/incidents")
async def create_incident(request: Request):
    body = await read_json(request)
    if body is None:
        return fail(400, "body must be JSON")
    try:
        engine.validate_create(body)
    except engine.Invalid as exc:
        return fail(422, str(exc))

    run_id = body["runId"]
    req_hash = engine.sha256_hex(engine.canonical(body))
    with LOCK:
        row = DB.execute("SELECT req_hash, state FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if row:
            if row[0] != req_hash:
                return fail(409, "runId already used with different content")
            return JSONResponse(json.loads(row[1])["createResponse"])
        try:
            state = engine.create_run(
                body,
                request.headers.get("traceparent"),
                request.headers.get("tracestate"),
            )
        except engine.Invalid as exc:
            return fail(422, str(exc))
        except httpx.HTTPStatusError as exc:
            log.warning("model HTTP %s", exc.response.status_code)
            return JSONResponse(
                {"error": "planning unavailable; retry later",
                 "detail": f"model HTTP {exc.response.status_code}"},
                status_code=503)
        except Exception as exc:
            log.exception("planning failed")
            return JSONResponse(
                {"error": "planning unavailable; retry later",
                 "detail": type(exc).__name__},
                status_code=503)
        DB.execute("INSERT INTO runs (run_id, req_hash, state) VALUES (?, ?, ?)",
                   (run_id, req_hash, json.dumps(state)))
        DB.commit()
    return JSONResponse(state["createResponse"])


@app.post("/v2/incidents/{run_id}/receipts")
async def post_receipt(run_id: str, request: Request):
    body = await read_json(request)
    if body is None:
        return fail(400, "body must be JSON")
    try:
        engine.validate_receipt(body)
    except engine.Invalid as exc:
        return fail(422, str(exc))

    receipt_id = body["receiptId"]
    req_hash = engine.sha256_hex(engine.canonical(body))
    with LOCK:
        seen = DB.execute("SELECT run_id, req_hash, response FROM receipts WHERE receipt_id = ?",
                          (receipt_id,)).fetchone()
        if seen:
            if seen[0] != run_id or seen[1] != req_hash:
                return fail(409, "receiptId already used with different content")
            return JSONResponse(json.loads(seen[2]))

        row = DB.execute("SELECT state FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not row:
            return fail(404, "unknown run")
        state = json.loads(row[0])
        try:
            response = engine.apply_receipt(state, body)
        except engine.Invalid as exc:
            return fail(422, str(exc))

        # Persist state and the replayable response together.
        DB.execute("UPDATE runs SET state = ? WHERE run_id = ?", (json.dumps(state), run_id))
        DB.execute("INSERT INTO receipts (receipt_id, run_id, req_hash, response) VALUES (?, ?, ?, ?)",
                   (receipt_id, run_id, req_hash, json.dumps(response)))
        DB.commit()
    return JSONResponse(response)


@app.get("/v2/incidents/{run_id}")
def get_incident(run_id: str):
    with LOCK:
        row = DB.execute("SELECT state FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    if not row:
        return fail(404, "unknown run")
    return JSONResponse(json.loads(row[0])["lastResponse"])
