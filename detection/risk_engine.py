import json
import requests
import shodan
from sqlalchemy.orm import sessionmaker
from config import Config
from database.models import IPReport, SearchHistory, create_tables

# Initialize database engine and sessionmaker
engine = create_tables()
SessionLocal = sessionmaker(bind=engine)


def calculate_risk_level(abuse_score):
    """Determine risk level based on AbuseIPDB abuse confidence score."""
    if abuse_score > 75:
        return "CRITICAL"
    elif abuse_score > 50:
        return "HIGH"
    elif abuse_score > 25:
        return "MEDIUM"
    else:
        return "LOW"


def analyze_ip(ip, db_session=None):
    """Analyze an IP address using AbuseIPDB and Shodan APIs, save results to DB, and return threat intelligence summary."""
    ip = ip.strip()
    
    # 1. Query AbuseIPDB API
    abuse_score = 0
    total_reports = 0
    country = "N/A"
    isp = "Unknown"
    
    api_key = getattr(Config, "ABUSEIPDB_API_KEY", "")
    if api_key:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": "true"
        }
        try:
            response = requests.get(url, headers=headers, params=params, timeout=8)
            if response.status_code == 200:
                data = response.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                total_reports = data.get("totalReports", 0)
                country = data.get("countryCode", "N/A")
                isp = data.get("isp", "Unknown")
        except Exception:
            pass

    # 2. Query Shodan API
    open_ports = []
    vulnerabilities = []
    
    shodan_key = getattr(Config, "SHODAN_API_KEY", "")
    if shodan_key:
        try:
            api = shodan.Shodan(shodan_key)
            host_info = api.host(ip)
            open_ports = host_info.get("ports", [])
            
            vulns = host_info.get("vulns", [])
            if isinstance(vulns, dict):
                vulnerabilities = list(vulns.keys())
            elif isinstance(vulns, list):
                vulnerabilities = vulns
            
            if country == "N/A":
                country = host_info.get("country_name", "N/A")
            if isp == "Unknown":
                isp = host_info.get("isp", "Unknown")
        except (shodan.APIError, Exception):
            # If Shodan has no data for the IP or errors out, keep shodan fields empty
            open_ports = []
            vulnerabilities = []

    # 3. Calculate risk level
    risk_level = calculate_risk_level(abuse_score)

    # 4. Save results to database (IPReport and SearchHistory)
    session = db_session if db_session is not None else SessionLocal()
    close_session_on_finish = (db_session is None)
    
    try:
        ip_report = IPReport(
            ip_address=ip,
            abuse_score=abuse_score,
            total_reports=total_reports,
            country=country,
            isp=isp,
            open_ports=json.dumps(open_ports),
            vulnerabilities=json.dumps(vulnerabilities),
            risk_level=risk_level
        )
        search_history = SearchHistory(
            ip_address=ip,
            risk_level=risk_level
        )
        session.add(ip_report)
        session.add(search_history)
        session.commit()
    except Exception as db_err:
        session.rollback()
    finally:
        if close_session_on_finish:
            session.close()

    # 5. Return formatted dictionary
    return {
        "ip": ip,
        "abuse_score": abuse_score,
        "total_reports": total_reports,
        "country": country,
        "isp": isp,
        "open_ports": open_ports,
        "vulnerabilities": vulnerabilities,
        "risk_level": risk_level
    }
