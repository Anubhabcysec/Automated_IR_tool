import os
import tempfile
import unittest

from response.pdf_generator import generate_pdf_report


class TestPDFGenerator(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_pdf = os.path.join(self.temp_dir.name, "test_report.pdf")

        self.sample_scan_data = {
            "target_ip": "192.168.1.100",
            "scan_time": "2026-08-12 10:00:00 UTC",
            "risk_level": "CRITICAL",
            "open_ports": [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service_name": "ssh",
                    "service_version": "OpenSSH 8.9p1",
                },
                {
                    "port": 80,
                    "protocol": "tcp",
                    "state": "open",
                    "service_name": "http",
                    "service_version": "Apache httpd 2.4.41",
                },
            ],
        }

        self.sample_cve_data = {
            "ssh 22": [
                {
                    "cve_id": "CVE-2023-1234",
                    "cvss_score": 9.8,
                    "severity": "CRITICAL",
                    "published_date": "2023-01-15",
                    "description": "Remote code execution vulnerability in SSH.",
                }
            ],
            "http 80": [
                {
                    "cve_id": "CVE-2022-5678",
                    "cvss_score": 7.5,
                    "severity": "HIGH",
                    "published_date": "2022-06-20",
                    "description": "Buffer overflow in web server component.",
                }
            ],
        }

        self.sample_mitre_data = [
            {
                "port": 22,
                "technique_id": "T1021.004",
                "tactic": "Lateral Movement",
                "technique_name": "Remote Services: SSH",
            },
            {
                "port": 80,
                "technique_id": "T1190",
                "tactic": "Initial Access",
                "technique_name": "Exploit Public-Facing Application",
            },
        ]

        self.sample_ai_analysis = (
            "## Risk Overview\n"
            "The target system exhibits a **CRITICAL** risk posture due to exposed remote services and high-severity CVEs.\n\n"
            "## Prioritised Vulnerabilities\n"
            "1. **CVE-2023-1234**: Unauthenticated remote code execution.\n\n"
            "## Immediate Remediation Steps\n"
            "- Update OpenSSH to the latest version.\n"
            "- Restrict port 22 access via firewall."
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_generate_pdf_report_creates_file(self):
        res_path = generate_pdf_report(
            scan_data=self.sample_scan_data,
            cve_data=self.sample_cve_data,
            mitre_data=self.sample_mitre_data,
            ai_analysis=self.sample_ai_analysis,
            output_path=self.output_pdf,
        )

        self.assertEqual(res_path, self.output_pdf)
        self.assertTrue(os.path.exists(self.output_pdf))
        self.assertGreater(os.path.getsize(self.output_pdf), 1000)

    def test_generate_pdf_report_empty_data(self):
        empty_pdf = os.path.join(self.temp_dir.name, "empty_report.pdf")
        res_path = generate_pdf_report(
            scan_data={},
            cve_data={},
            mitre_data=[],
            ai_analysis="",
            output_path=empty_pdf,
        )

        self.assertEqual(res_path, empty_pdf)
        self.assertTrue(os.path.exists(empty_pdf))
        self.assertGreater(os.path.getsize(empty_pdf), 500)


if __name__ == "__main__":
    unittest.main()
