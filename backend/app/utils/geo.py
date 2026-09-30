from __future__ import annotations

import math

# Coarse city centroids used for synthetic geo features (no precise locations are stored).
CITY_COORDS: dict[str, tuple[float, float]] = {
    "Mumbai": (19.076, 72.8777),
    "Delhi": (28.7041, 77.1025),
    "Bengaluru": (12.9716, 77.5946),
    "Chennai": (13.0827, 80.2707),
    "Kolkata": (22.5726, 88.3639),
    "Hyderabad": (17.385, 78.4867),
    "Pune": (18.5204, 73.8567),
    "Ahmedabad": (23.0225, 72.5714),
    "Jaipur": (26.9124, 75.7873),
    "Lucknow": (26.8467, 80.9462),
    "Kochi": (9.9312, 76.2673),
    "Guwahati": (26.1445, 91.7362),
    "Singapore": (1.3521, 103.8198),
    "Dubai": (25.2048, 55.2708),
    "Frankfurt": (50.1109, 8.6821),
}


def coords_for(city: str | None) -> tuple[float, float] | None:
    if not city:
        return None
    return CITY_COORDS.get(city)


def haversine_km(a: tuple[float, float] | None, b: tuple[float, float] | None) -> float:
    if a is None or b is None:
        return 0.0
    lat1, lon1 = map(math.radians, a)
    lat2, lon2 = map(math.radians, b)
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(h))
