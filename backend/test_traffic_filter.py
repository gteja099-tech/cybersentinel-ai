import unittest
from backend.app import (
    is_internal_or_polling_event,
    _normalize_event,
    TRAFFIC_EVENTS,
    app,
)
from fastapi.testclient import TestClient

client = TestClient(app)


class TestTrafficEventFiltering(unittest.TestCase):
    def setUp(self):
        TRAFFIC_EVENTS.clear()

    def test_internal_polling_excluded(self):
        polling_cases = [
            {"path": "/api/live-predictions", "method": "GET"},
            {"path": "/api/live-predictions?limit=10", "method": "GET"},
            {"path": "/api/recent-predictions", "method": "GET"},
            {"path": "/api/recent-predictions?limit=50", "method": "GET"},
            {"path": "/api/traffic-events", "method": "GET"},
            {"path": "/api/traffic-events?limit=50", "method": "GET"},
            {"path": "/api/request-log", "method": "GET"},
            {"path": "/api/request-log?limit=100", "method": "GET"},
            {"path": "/health", "method": "GET"},
            {"path": "/health/", "method": "GET"},
            {"path": "/api/capture-status", "method": "GET"},
            {"path": "/api/flow-features", "method": "GET"},
            {"path": "/api/feature-columns", "method": "GET"},
            {"path": "/api/ingest-flow", "method": "POST"},
            {"path": "/predict-csv", "method": "POST"},
            {"path": "/predict", "method": "POST"},
        ]
        for case in polling_cases:
            with self.subTest(case=case):
                self.assertTrue(
                    is_internal_or_polling_event(case),
                    f"Expected {case['path']} to be classified as internal polling",
                )

    def test_genuine_novatech_events_included(self):
        genuine_cases = [
            {"path": "/", "method": "GET"},
            {"path": "/about", "method": "GET"},
            {"path": "/products", "method": "GET"},
            {"path": "/products?category=cybersecurity", "method": "GET"},
            {"path": "/contact", "method": "GET"},
            {"path": "/login", "method": "GET"},
            {"path": "/api/contact", "method": "POST"},
            {"path": "/api/contact-demo", "method": "POST"},
            {"path": "/api/login", "method": "POST"},
            {"path": "/styles.css", "method": "GET"},
            {"path": "/script.js", "method": "GET"},
            {"path": "/pricing", "method": "GET"},
            {"path": "/admin/attempt", "method": "GET"},
        ]
        for case in genuine_cases:
            with self.subTest(case=case):
                self.assertFalse(
                    is_internal_or_polling_event(case),
                    f"Expected {case['path']} to be classified as genuine traffic",
                )

    def test_api_ingest_polling_vs_genuine(self):
        # 1. Send polling request -> should be excluded
        res_poll = client.post(
            "/api/traffic-events",
            json={
                "id": "poll-1",
                "path": "/api/live-predictions",
                "query": "limit=10",
                "method": "GET",
                "status_code": 200,
                "response_time_ms": 1.2,
            },
        )
        self.assertEqual(res_poll.status_code, 200)
        self.assertTrue(res_poll.json().get("excluded"))
        self.assertEqual(len(TRAFFIC_EVENTS), 0)

        # 2. Another polling request (/api/recent-predictions) -> should be excluded
        res_poll2 = client.post(
            "/api/traffic-events",
            json={
                "id": "poll-2",
                "path": "/api/recent-predictions",
                "query": "limit=50",
                "method": "GET",
                "status_code": 200,
                "response_time_ms": 0.8,
            },
        )
        self.assertEqual(res_poll2.status_code, 200)
        self.assertTrue(res_poll2.json().get("excluded"))
        self.assertEqual(len(TRAFFIC_EVENTS), 0)

        # 3. Genuine request (/products) -> should be stored
        res_gen = client.post(
            "/api/traffic-events",
            json={
                "id": "gen-1",
                "path": "/products",
                "query": "category=enterprise",
                "method": "GET",
                "status_code": 200,
                "response_time_ms": 3.4,
            },
        )
        self.assertEqual(res_gen.status_code, 200)
        self.assertFalse(res_gen.json().get("excluded", False))
        self.assertEqual(len(TRAFFIC_EVENTS), 1)

        # 4. Genuine request (/about) -> should be stored
        res_gen2 = client.post(
            "/api/traffic-events",
            json={
                "id": "gen-2",
                "path": "/about",
                "method": "GET",
                "status_code": 200,
                "response_time_ms": 1.1,
            },
        )
        self.assertEqual(res_gen2.status_code, 200)
        self.assertEqual(len(TRAFFIC_EVENTS), 2)

        # Verify GET /api/traffic-events only returns genuine events
        get_res = client.get("/api/traffic-events?limit=50")
        self.assertEqual(get_res.status_code, 200)
        data = get_res.json()
        self.assertEqual(data["total_stored"], 2)
        self.assertEqual(data["returned"], 2)
        paths = [e["path"] for e in data["events"]]
        self.assertIn("/products", paths)
        self.assertIn("/about", paths)
        self.assertNotIn("/api/live-predictions", paths)
        self.assertNotIn("/api/recent-predictions", paths)

    def test_batch_ingestion_filtering(self):
        batch = [
            {"id": "b1", "path": "/api/live-predictions", "method": "GET"},
            {"id": "b2", "path": "/about", "method": "GET"},
            {"id": "b3", "path": "/health", "method": "GET"},
            {"id": "b4", "path": "/api/login", "method": "POST"},
        ]
        res = client.post("/api/traffic-events", json=batch)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(TRAFFIC_EVENTS), 2)
        stored_ids = [e["id"] for e in TRAFFIC_EVENTS]
        self.assertEqual(stored_ids, ["b2", "b4"])

    def test_get_traffic_events_filters_preexisting_internal_events(self):
        # Directly put an unfiltered event in deque to simulate preexisting data
        TRAFFIC_EVENTS.append(_normalize_event({"id": "legacy-poll", "path": "/api/live-predictions"}))
        TRAFFIC_EVENTS.append(_normalize_event({"id": "legacy-real", "path": "/products"}))

        get_res = client.get("/api/traffic-events?limit=50")
        self.assertEqual(get_res.status_code, 200)
        data = get_res.json()
        self.assertEqual(data["total_stored"], 1)
        self.assertEqual(data["returned"], 1)
        self.assertEqual(data["events"][0]["path"], "/products")


if __name__ == "__main__":
    unittest.main()
