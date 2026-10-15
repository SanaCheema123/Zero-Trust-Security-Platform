"""Elasticsearch integration.

The platform works with or without Elasticsearch:
- if ES is reachable, events/traffic are indexed and search goes through ES;
- otherwise everything falls back to PostgreSQL, so the app never breaks.
"""

import logging
import os

from elasticsearch import Elasticsearch

logger = logging.getLogger(__name__)

ES_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
ES_EVENT_INDEX = os.getenv("ES_EVENT_INDEX", "security_events")
ES_TRAFFIC_INDEX = os.getenv("ES_TRAFFIC_INDEX", "network_traffic")

_client = None
_checked = False


def _get_client():
    global _client, _checked
    if _checked:
        return _client
    _checked = True
    try:
        candidate = Elasticsearch(
            ES_URL,
            request_timeout=2,
            max_retries=1,
            retry_on_timeout=False,
        )
        if candidate.ping():
            _client = candidate
            logger.info("Connected to Elasticsearch at %s", ES_URL)
        else:
            logger.warning(
                "Elasticsearch at %s is not reachable - using PostgreSQL fallback",
                ES_URL,
            )
    except Exception as exc:
        logger.warning(
            "Elasticsearch unavailable (%s) - using PostgreSQL fallback", exc
        )
    return _client


def available() -> bool:
    return _get_client() is not None


def _ensure_index(index: str):
    client = _get_client()
    if client is None:
        return
    try:
        if not client.indices.exists(index=index):
            client.indices.create(index=index)
    except Exception as exc:
        logger.debug("Index creation skipped: %s", exc)


def index_event(event_dict: dict):
    client = _get_client()
    if client is None:
        return False
    try:
        _ensure_index(ES_EVENT_INDEX)
        client.index(index=ES_EVENT_INDEX, id=event_dict["id"], document=event_dict)
        return True
    except Exception as exc:
        logger.warning("Failed to index security event: %s", exc)
        return False


def index_traffic(traffic_dict: dict):
    client = _get_client()
    if client is None:
        return False
    try:
        _ensure_index(ES_TRAFFIC_INDEX)
        client.index(index=ES_TRAFFIC_INDEX, id=traffic_dict["id"], document=traffic_dict)
        return True
    except Exception as exc:
        logger.warning("Failed to index traffic: %s", exc)
        return False


def search(query: str, index: str | None = None, size: int = 50) -> list:
    """Search events/traffic. Returns [] when ES is unavailable."""
    client = _get_client()
    if client is None:
        return []
    indices = index or f"{ES_EVENT_INDEX},{ES_TRAFFIC_INDEX}"
    try:
        result = client.search(
            index=indices,
            q=query,
            size=size,
        )
        hits = []
        for hit in result.get("hits", {}).get("hits", []):
            doc = hit.get("_source", {})
            doc["_index"] = hit.get("_index")
            hits.append(doc)
        return hits
    except Exception as exc:
        logger.warning("Elasticsearch search failed: %s", exc)
        return []