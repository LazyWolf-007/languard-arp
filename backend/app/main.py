from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api import router

app = FastAPI(title="LANGuard ARP", version="1.0.0", description="Safe, simulated ARP spoofing detection lab")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_credentials=False, allow_methods=["*"], allow_headers=["*"])
app.include_router(router)

@app.get("/api/health")
def health(): return {"status": "ok", "network_access": "simulation only"}
