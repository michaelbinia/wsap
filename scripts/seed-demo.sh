#!/usr/bin/env bash
# Seed the running Mini WSA with ~10 handcrafted events covering a mix of
# categories and actions, plus a 6-event burst from one clientIp so the
# repeat-offender bonus fires.
#
# Override the target with: BASE=http://host:8080 ./scripts/seed-demo.sh
set -euo pipefail

BASE="${BASE:-http://localhost:8080}"

curl --fail-with-body -sS -X POST "$BASE/v1/events/ingest" \
    -H 'Content-Type: application/json' \
    -d '[
      {
        "eventId": "evt-demo-001", "timestamp": "2026-05-20T14:32:10Z", "configId": 14227, "policyId": "pol_web1",
        "clientIp": "203.0.113.42", "hostname": "www.example.com", "path": "/api/v1/login",
        "method": "POST", "statusCode": 403, "userAgent": "curl/8.4.0",
        "rule": {"id": "950001", "name": "SQL_INJECTION", "message": "SQL Injection Attack Detected", "severity": "CRITICAL", "category": "INJECTION"},
        "action": "DENY", "geoLocation": {"country": "CN", "city": "Beijing"},
        "requestSize": 1024, "responseSize": 256
      },
      {
        "eventId": "evt-demo-002", "timestamp": "2026-05-20T14:32:15Z", "configId": 14227, "policyId": "pol_web1",
        "clientIp": "198.51.100.17", "hostname": "api.example.com", "path": "/search",
        "method": "GET", "statusCode": 200, "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "rule": {"id": "941100", "name": "XSS_ATTACK", "message": "Cross-Site Scripting Attempt", "severity": "HIGH", "category": "XSS"},
        "action": "ALERT", "geoLocation": {"country": "US", "city": "San Francisco"},
        "requestSize": 512, "responseSize": 2048
      },
      {
        "eventId": "evt-demo-003", "timestamp": "2026-05-20T14:33:00Z", "configId": 14228, "policyId": "pol_web2",
        "clientIp": "192.0.2.5", "hostname": "www.example.com", "path": "/robots.txt",
        "method": "GET", "statusCode": 200, "userAgent": "GoogleBot/2.1 (+http://www.google.com/bot.html)",
        "rule": {"id": "913001", "name": "BOT_ACTIVITY", "message": "Automated Bot Request", "severity": "LOW", "category": "BOT"},
        "action": "MONITOR", "geoLocation": {"country": "US", "city": "Mountain View"},
        "requestSize": 128, "responseSize": 64
      },
      {
        "eventId": "evt-demo-burst-1", "timestamp": "2026-05-20T14:40:00Z", "configId": 14227, "policyId": "pol_web1",
        "clientIp": "203.0.113.99", "hostname": "www.example.com", "path": "/admin",
        "method": "POST", "statusCode": 401, "userAgent": "curl/8.4.0",
        "rule": {"id": "950001", "name": "SQL_INJECTION", "message": "SQL Injection Attack Detected", "severity": "CRITICAL", "category": "INJECTION"},
        "action": "DENY", "geoLocation": {"country": "RU", "city": "Moscow"},
        "requestSize": 2048, "responseSize": 256
      },
      {
        "eventId": "evt-demo-burst-2", "timestamp": "2026-05-20T14:40:10Z", "configId": 14227, "policyId": "pol_web1",
        "clientIp": "203.0.113.99", "hostname": "www.example.com", "path": "/admin",
        "method": "POST", "statusCode": 401, "userAgent": "curl/8.4.0",
        "rule": {"id": "950001", "name": "SQL_INJECTION", "message": "SQL Injection Attack Detected", "severity": "CRITICAL", "category": "INJECTION"},
        "action": "DENY", "geoLocation": {"country": "RU", "city": "Moscow"},
        "requestSize": 2048, "responseSize": 256
      },
      {
        "eventId": "evt-demo-burst-3", "timestamp": "2026-05-20T14:40:20Z", "configId": 14227, "policyId": "pol_web1",
        "clientIp": "203.0.113.99", "hostname": "www.example.com", "path": "/admin",
        "method": "POST", "statusCode": 401, "userAgent": "curl/8.4.0",
        "rule": {"id": "950001", "name": "SQL_INJECTION", "message": "SQL Injection Attack Detected", "severity": "CRITICAL", "category": "INJECTION"},
        "action": "DENY", "geoLocation": {"country": "RU", "city": "Moscow"},
        "requestSize": 2048, "responseSize": 256
      },
      {
        "eventId": "evt-demo-burst-4", "timestamp": "2026-05-20T14:40:30Z", "configId": 14227, "policyId": "pol_web1",
        "clientIp": "203.0.113.99", "hostname": "www.example.com", "path": "/admin",
        "method": "POST", "statusCode": 401, "userAgent": "curl/8.4.0",
        "rule": {"id": "950001", "name": "SQL_INJECTION", "message": "SQL Injection Attack Detected", "severity": "CRITICAL", "category": "INJECTION"},
        "action": "DENY", "geoLocation": {"country": "RU", "city": "Moscow"},
        "requestSize": 2048, "responseSize": 256
      },
      {
        "eventId": "evt-demo-burst-5", "timestamp": "2026-05-20T14:40:40Z", "configId": 14227, "policyId": "pol_web1",
        "clientIp": "203.0.113.99", "hostname": "www.example.com", "path": "/admin",
        "method": "POST", "statusCode": 401, "userAgent": "curl/8.4.0",
        "rule": {"id": "950001", "name": "SQL_INJECTION", "message": "SQL Injection Attack Detected", "severity": "CRITICAL", "category": "INJECTION"},
        "action": "DENY", "geoLocation": {"country": "RU", "city": "Moscow"},
        "requestSize": 2048, "responseSize": 256
      },
      {
        "eventId": "evt-demo-burst-6", "timestamp": "2026-05-20T14:40:50Z", "configId": 14227, "policyId": "pol_web1",
        "clientIp": "203.0.113.99", "hostname": "www.example.com", "path": "/admin",
        "method": "POST", "statusCode": 401, "userAgent": "curl/8.4.0",
        "rule": {"id": "950001", "name": "SQL_INJECTION", "message": "SQL Injection Attack Detected", "severity": "CRITICAL", "category": "INJECTION"},
        "action": "DENY", "geoLocation": {"country": "RU", "city": "Moscow"},
        "requestSize": 2048, "responseSize": 256
      },
      {
        "eventId": "evt-demo-burst-7", "timestamp": "2026-05-20T14:41:00Z", "configId": 14227, "policyId": "pol_web1",
        "clientIp": "203.0.113.99", "hostname": "www.example.com", "path": "/admin",
        "method": "POST", "statusCode": 401, "userAgent": "curl/8.4.0",
        "rule": {"id": "950001", "name": "SQL_INJECTION", "message": "SQL Injection Attack Detected", "severity": "CRITICAL", "category": "INJECTION"},
        "action": "DENY", "geoLocation": {"country": "RU", "city": "Moscow"},
        "requestSize": 2048, "responseSize": 256
      }
    ]'

echo
echo "Seeded. Try: curl -s $BASE/v1/stats/summary | jq"
