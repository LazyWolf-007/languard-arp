import json
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from .engine import process
from .models import Mode, Observation
from .simulation import demo_observations, gateway_spoof_observation, normal_observation
from .state import state

router = APIRouter()
clients: set[WebSocket] = set()

async def broadcast():
    payload = json.loads(state.snapshot().model_dump_json())
    dead = []
    for ws in clients:
        try: await ws.send_json(payload)
        except Exception: dead.append(ws)
    for ws in dead: clients.discard(ws)

async def record(obs: Observation):
    if not state.monitoring: raise HTTPException(409, "Monitoring is stopped")
    if obs.scenario and any(e.scenario == obs.scenario for e in state.events):
        raise HTTPException(409, "Duplicate scenario observation")
    result = process(obs, state.mappings, state.mode, state.alerts, state.decisions, state.events, state.id)
    await broadcast()
    return {"alert": result[0], "event": result[1], "snapshot": state.snapshot()}

@router.get("/api/state")
def get_state(): return state.snapshot()

@router.post("/api/observations")
async def observe(obs: Observation): return await record(obs)

@router.post("/api/mode/{mode}")
async def set_mode(mode: Mode):
    state.mode = mode
    await broadcast()
    return state.snapshot()

@router.post("/api/monitoring/{action}")
async def monitoring(action: str):
    if action not in {"start", "stop"}: raise HTTPException(422, "Action must be start or stop")
    state.monitoring = action == "start"
    await broadcast()
    return state.snapshot()

@router.post("/api/simulation/normal")
async def normal():
    return await record(normal_observation(state.id("normal")))

@router.post("/api/simulation/spoof")
async def spoof():
    return await record(gateway_spoof_observation(state.id("spoof")))

@router.post("/api/simulation/demo")
async def demo():
    if not state.monitoring: raise HTTPException(409, "Start the simulation before running the demo")
    results = []
    for obs in demo_observations(state.id):
        results.append(process(obs, state.mappings, state.mode, state.alerts, state.decisions, state.events, state.id))
    await broadcast()
    return state.snapshot()

@router.post("/api/reset")
async def reset():
    state.reset()
    await broadcast()
    return state.snapshot()

@router.websocket("/api/ws")
async def websocket(ws: WebSocket):
    await ws.accept(); clients.add(ws)
    await ws.send_json(json.loads(state.snapshot().model_dump_json()))
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect: clients.discard(ws)
