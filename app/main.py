import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from api.routes import router
from geo.lookup import init_readers


@asynccontextmanager
async def lifespan(app: FastAPI):
    city_db = os.environ.get("GEOIP_CITY_DB", "/data/geoip/GeoLite2-City.mmdb")
    asn_db = os.environ.get("GEOIP_ASN_DB", "/data/geoip/GeoLite2-ASN.mmdb")
    init_readers(city_db, asn_db)
    yield


app = FastAPI(title="AtomicWatch", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "ok"}


app.include_router(router, prefix="/api")

# StaticFiles en dernier — catch-all pour le frontend
app.mount("/", StaticFiles(directory="static", html=True), name="static")
