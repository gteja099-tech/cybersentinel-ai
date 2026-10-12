import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { isGenuineTrafficEvent, EXCLUDED_TRAFFIC_PREFIXES } from './services/api.js';

describe('Frontend Live Traffic Event Filtering & Response Handling', () => {
  test('EXCLUDED_TRAFFIC_PREFIXES contains all required internal/polling endpoints', () => {
    const required = [
      '/api/live-predictions',
      '/api/recent-predictions',
      '/api/traffic-events',
      '/api/request-log',
      '/health',
    ];
    for (const prefix of required) {
      assert.ok(
        EXCLUDED_TRAFFIC_PREFIXES.includes(prefix),
        `Missing prefix: ${prefix}`
      );
    }
  });

  test('isGenuineTrafficEvent excludes internal polling requests', () => {
    const pollingRequests = [
      { path: '/api/live-predictions', method: 'GET' },
      { path: '/api/live-predictions?limit=10', method: 'GET' },
      { path: '/api/recent-predictions', method: 'GET' },
      { path: '/api/recent-predictions?limit=50', method: 'GET' },
      { path: '/api/traffic-events', method: 'GET' },
      { path: '/api/traffic-events?limit=50', method: 'GET' },
      { path: '/api/request-log', method: 'GET' },
      { path: '/api/request-log?limit=100', method: 'GET' },
      { path: '/health', method: 'GET' },
      { path: '/health/', method: 'GET' },
      { path: '/api/capture-status', method: 'GET' },
      { path: '/api/flow-features', method: 'GET' },
      { path: '/api/feature-columns', method: 'GET' },
      { path: '/api/ingest-flow', method: 'POST' },
      { path: '/predict-csv', method: 'POST' },
      { path: '/predict', method: 'POST' },
    ];

    for (const req of pollingRequests) {
      assert.equal(
        isGenuineTrafficEvent(req),
        false,
        `Expected ${req.path} to be excluded`
      );
    }
  });

  test('isGenuineTrafficEvent preserves genuine NovaTech pages and assets', () => {
    const genuineRequests = [
      { path: '/', method: 'GET' },
      { path: '/about', method: 'GET' },
      { path: '/products', method: 'GET' },
      { path: '/products?category=cybersecurity', method: 'GET' },
      { path: '/contact', method: 'GET' },
      { path: '/login', method: 'GET' },
      { path: '/api/contact', method: 'POST' },
      { path: '/api/login', method: 'POST' },
      { path: '/styles.css', method: 'GET' },
      { path: '/script.js', method: 'GET' },
      { path: '/favicon.ico', method: 'GET' },
    ];

    for (const req of genuineRequests) {
      assert.equal(
        isGenuineTrafficEvent(req),
        true,
        `Expected ${req.path} to be preserved`
      );
    }
  });

  test('Dashboard response handling strips polling events and accurately sets total count', () => {
    // Simulating production API payload with polling requests + genuine events
    const rawApiResponse = {
      total_stored: 63,
      returned: 50,
      events: [
        { id: '1', path: '/api/recent-predictions', method: 'GET' },
        { id: '2', path: '/api/live-predictions', method: 'GET' },
        { id: '3', path: '/products', method: 'GET' },
        { id: '4', path: '/about', method: 'GET' },
        { id: '5', path: '/api/request-log', method: 'GET' },
        { id: '6', path: '/', method: 'GET' },
      ],
    };

    const rawList = rawApiResponse.events;
    const genuineList = rawList.filter(isGenuineTrafficEvent);

    const total =
      typeof rawApiResponse.total_stored === 'number' && rawList.length === genuineList.length
        ? rawApiResponse.total_stored
        : genuineList.length;

    // Verify polling requests were removed
    assert.equal(genuineList.length, 3);
    assert.deepEqual(
      genuineList.map((e) => e.path),
      ['/products', '/about', '/']
    );

    // Verify total count uses genuine count (3) instead of contaminated total_stored (63)
    assert.equal(total, 3);
  });
});
