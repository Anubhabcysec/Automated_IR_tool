import unittest
from unittest.mock import patch, MagicMock
from sqlalchemy.orm import sessionmaker
from database.models import IPReport, SearchHistory, create_tables
from detection.risk_engine import analyze_ip, calculate_risk_level

class TestRiskEngine(unittest.TestCase):
    def setUp(self):
        self.engine = create_tables("sqlite:///:memory:")
        self.Session = sessionmaker(bind=self.engine)

    def test_calculate_risk_level(self):
        self.assertEqual(calculate_risk_level(80), "CRITICAL")
        self.assertEqual(calculate_risk_level(60), "HIGH")
        self.assertEqual(calculate_risk_level(30), "MEDIUM")
        self.assertEqual(calculate_risk_level(10), "LOW")

    @patch('detection.risk_engine.requests.get')
    @patch('detection.risk_engine.shodan.Shodan')
    def test_analyze_ip_mocked_and_saved_to_db(self, mock_shodan, mock_get):
        session = self.Session()
        
        # Mock AbuseIPDB response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "abuseConfidenceScore": 85,
                "totalReports": 42,
                "countryCode": "US",
                "isp": "BadHost Inc"
            }
        }
        mock_get.return_value = mock_response

        # Mock Shodan response
        mock_shodan_inst = MagicMock()
        mock_shodan_inst.host.return_value = {
            "ports": [80, 443, 22],
            "vulns": {"CVE-2023-1234": {}}
        }
        mock_shodan.return_value = mock_shodan_inst

        res = analyze_ip("8.8.8.8", db_session=session)
        self.assertEqual(res["ip"], "8.8.8.8")
        self.assertEqual(res["abuse_score"], 85)
        self.assertEqual(res["total_reports"], 42)
        self.assertEqual(res["country"], "US")
        self.assertEqual(res["isp"], "BadHost Inc")
        self.assertEqual(res["open_ports"], [80, 443, 22])
        self.assertEqual(res["vulnerabilities"], ["CVE-2023-1234"])
        self.assertEqual(res["risk_level"], "CRITICAL")

        # Verify IPReport record created in DB
        report = session.query(IPReport).filter_by(ip_address="8.8.8.8").first()
        self.assertIsNotNone(report)
        self.assertEqual(report.abuse_score, 85)
        self.assertEqual(report.risk_level, "CRITICAL")

        # Verify SearchHistory record created in DB
        history = session.query(SearchHistory).filter_by(ip_address="8.8.8.8").first()
        self.assertIsNotNone(history)
        self.assertEqual(history.risk_level, "CRITICAL")

    @patch('detection.risk_engine.requests.get')
    @patch('detection.risk_engine.shodan.Shodan')
    def test_analyze_ip_shodan_failure(self, mock_shodan, mock_get):
        session = self.Session()
        
        # Mock AbuseIPDB response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "abuseConfidenceScore": 10,
                "totalReports": 1,
                "countryCode": "US",
                "isp": "GoodHost Inc"
            }
        }
        mock_get.return_value = mock_response

        # Mock Shodan exception
        mock_shodan_inst = MagicMock()
        mock_shodan_inst.host.side_effect = Exception("No data")
        mock_shodan.return_value = mock_shodan_inst

        res = analyze_ip("1.1.1.1", db_session=session)
        self.assertEqual(res["ip"], "1.1.1.1")
        self.assertEqual(res["abuse_score"], 10)
        self.assertEqual(res["open_ports"], [])
        self.assertEqual(res["vulnerabilities"], [])
        self.assertEqual(res["risk_level"], "LOW")

        # Verify DB records
        report = session.query(IPReport).filter_by(ip_address="1.1.1.1").first()
        self.assertIsNotNone(report)
        self.assertEqual(report.risk_level, "LOW")

if __name__ == '__main__':
    unittest.main()
