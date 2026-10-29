from __future__ import annotations

from fastapi import FastAPI

from pki_provisioning.api import app as pki_app

app = FastAPI(title="PKI Provisioning Service", version="0.1.0")
app.mount("/api", pki_app)


@app.get("/")
def root() -> dict[str, str]:
    return {"message": "PKI Provisioning API"}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "pki-provisioning"}
