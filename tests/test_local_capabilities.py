import tempfile
import unittest
from pathlib import Path

from app import database
from app.services import correlation_service, siem_service, response_service


class LocalCapabilitiesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        database.DATABASE_DIR = root
        database.DATABASE_FILE = root / "test.db"
        database.SCHEMA_FILE = Path(__file__).parents[1] / "database" / "schema.sql"
        database.initialize_database()
        conn = database.get_connection()
        conn.executescript("""
          INSERT INTO users(username,email) VALUES('admin','admin@example.test');
          INSERT INTO safes(name) VALUES('safe');
          INSERT INTO platforms(name) VALUES('Windows');
          INSERT INTO privileged_accounts(username,hostname,platform_id,safe_id,credential_hash,status)
          VALUES('Administrator','host1',1,1,'hash','ACTIVE');
          INSERT INTO sessions(session_id,user_id,account_id,start_time,end_time,status,source_ip,reason)
          VALUES('S1',1,1,'2026-01-01T10:00:00+00:00','2026-01-01T11:00:00+00:00','ACTIVE','10.0.0.5','test');
        """)
        conn.commit()
        conn.close()
        correlation_service.REPORT_FILE = str(root / "correlation.json")

    def tearDown(self):
        self.temp.cleanup()

    def test_temporal_correlation_requires_overlap(self):
        incidents = [{"incident_id": "I1", "incident_type": "TEST", "severity": "HIGH",
                      "source_ip": "10.0.0.5", "username": "Administrator", "hostname": "host1",
                      "event_timestamp": "2026-01-01T10:30:00+00:00"},
                     {"incident_id": "I2", "incident_type": "TEST", "severity": "HIGH",
                      "source_ip": "10.0.0.5", "username": "Administrator", "hostname": "host1",
                      "event_timestamp": "2026-01-01T12:00:00+00:00"}]
        correlation_service.correlate_incidents_with_pam(incidents)
        import json
        results = json.loads(Path(correlation_service.REPORT_FILE).read_text())["results"]
        self.assertEqual(results[0]["correlation_level"], "SESSION_SOURCE_MATCH")
        self.assertEqual(results[1]["correlation_level"], "ACCOUNT_AND_IP_MATCH_OUTSIDE_SESSION")

    def test_siem_ingestion_and_response_audit(self):
        incident = {"incident_id": "I3", "incident_type": "TEST", "severity": "HIGH",
                    "source_ip": "10.0.0.5", "username": "Administrator", "hostname": "host1"}
        self.assertEqual(siem_service.ingest_incidents([incident]), 1)
        self.assertEqual(len(siem_service.search_events("I3")), 1)
        ok, _ = response_service.respond("disable-account", "I3", "Administrator", "host1")
        self.assertTrue(ok)
        conn = database.get_connection()
        self.assertEqual(conn.execute("SELECT status FROM privileged_accounts WHERE id=1").fetchone()[0], "DISABLED")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit_logs WHERE event_type='AUTOMATED_RESPONSE'").fetchone()[0], 1)
        conn.close()


if __name__ == "__main__":
    unittest.main()
