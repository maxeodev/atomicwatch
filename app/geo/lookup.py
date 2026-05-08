import os
import geoip2.database
import geoip2.errors

_city_reader: geoip2.database.Reader | None = None
_asn_reader: geoip2.database.Reader | None = None


def init_readers(city_db: str, asn_db: str) -> None:
    global _city_reader, _asn_reader
    if os.path.exists(city_db):
        _city_reader = geoip2.database.Reader(city_db)
    if os.path.exists(asn_db):
        _asn_reader = geoip2.database.Reader(asn_db)


def lookup(ip: str) -> dict:
    result = {
        "country_code": "XX",
        "country_name": "Unknown",
        "latitude": 0.0,
        "longitude": 0.0,
        "asn": None,
        "org": None,
        "flag": "🏴",
    }

    if _city_reader:
        try:
            r = _city_reader.city(ip)
            result["country_code"] = r.country.iso_code or "XX"
            result["country_name"] = r.country.name or "Unknown"
            result["latitude"] = float(r.location.latitude or 0)
            result["longitude"] = float(r.location.longitude or 0)
            result["flag"] = _country_flag(result["country_code"])
        except (geoip2.errors.AddressNotFoundError, Exception):
            pass

    if _asn_reader:
        try:
            r = _asn_reader.asn(ip)
            result["asn"] = r.autonomous_system_number
            result["org"] = r.autonomous_system_organization
        except (geoip2.errors.AddressNotFoundError, Exception):
            pass

    return result


def _country_flag(code: str) -> str:
    if len(code) != 2:
        return "🏴"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())
