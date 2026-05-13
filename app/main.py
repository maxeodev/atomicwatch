import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from api.routes import router, _get_cowrie_sessions, _get_cowrie_summary_data
from geo.lookup import init_readers


async def _warmup():
    await asyncio.sleep(2)
    await _get_cowrie_sessions()
    await _get_cowrie_summary_data()


@asynccontextmanager
async def lifespan(app: FastAPI):
    city_db = os.environ.get("GEOIP_CITY_DB", "/data/geoip/GeoLite2-City.mmdb")
    asn_db = os.environ.get("GEOIP_ASN_DB", "/data/geoip/GeoLite2-ASN.mmdb")
    init_readers(city_db, asn_db)
    asyncio.create_task(_warmup())
    yield


APP_VERSION = "0.2.13"

app = FastAPI(title="AtomicWatch", version=APP_VERSION, lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "ok", "version": APP_VERSION}


app.include_router(router, prefix="/api")

# StaticFiles en dernier — catch-all pour le frontend
app.mount("/", StaticFiles(directory="static", html=True), name="static")
