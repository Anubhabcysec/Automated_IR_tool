import os
import json
import ipaddress
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_file
from sqlalchemy.orm import sessionmaker

from config import Config
from database.models import SearchHistory, IPReport, create_tables
from detection.risk_engine import analyze_ip
from parser.nmap_scanner import scan_target, get_local_ip
from detection.cve_lookup import get_cves_for_service
from detection.mitre_mapper import map_ports_to_mitre
from detection.ai_analyzer import analyze_with_ai
from response.pdf_generator import generate_pdf_report

app = Flask(
    __name__,
    template_folder='dashboard/templates',
    static_folder='dashboard/static'
)
app.config.from_object(Config)

# Initialize database engine and sessionmaker
engine = create_tables()
SessionLocal = sessionmaker(bind=engine)


def is_valid_ip(ip_str):
    """Validate whether the given string is a valid IPv4 or IPv6 address format."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


# --- FLASK ROUTES ---

@app.route('/')
def home():
    """Home page where user enters an IP address."""
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    """POST route that accepts an IP address and redirects to report page."""
    ip = request.form.get('ip', '').strip()
    
    # Validation
    if not ip or not is_valid_ip(ip):
        flash(f"'{ip}' is not a valid IPv4 or IPv6 address format.", "error")
        return redirect(url_for('home'))

    return redirect(url_for('report', ip=ip))


@app.route('/report/<ip>')
def report(ip):
    """Shows full threat report for a given IP address by calling analyze_ip()."""
    ip = ip.strip()
    
    # Basic IP address format validation before querying
    if not is_valid_ip(ip):
        flash(f"'{ip}' is not a valid IPv4 or IPv6 address format.", "error")
        return redirect(url_for('home'))

    # Call analyze_ip from detection.risk_engine
    result = analyze_ip(ip)

    # Format helpers for template compatibility
    abuse_data = {
        "abuseConfidenceScore": result.get("abuse_score", 0),
        "totalReports": result.get("total_reports", 0),
        "countryCode": result.get("country", "N/A"),
        "countryName": "",
        "isp": result.get("isp", "Unknown"),
        "domain": "N/A",
        "usageType": "N/A",
        "isWhitelisted": False
    }

    shodan_data = {
        "ports": result.get("open_ports", []),
        "vulns": result.get("vulnerabilities", []),
        "isp": result.get("isp", "Unknown"),
        "org": result.get("isp", "Unknown"),
        "os": "Unknown / Undetected",
        "hostnames": []
    }

    pretty_json = json.dumps(result, indent=2)

    return render_template(
        'report.html',
        ip=ip,
        result=result,
        abuse=abuse_data,
        shodan=shodan_data,
        raw_json_pretty=pretty_json
    )


@app.route('/api/analyze/<ip>')
def api_analyze(ip):
    """JSON endpoint that validates IP, calls analyze_ip(), and returns combined results as JSON."""
    ip = ip.strip()
    
    # Basic IP address format validation before querying
    if not is_valid_ip(ip):
        return jsonify({
            "status": "error",
            "message": f"'{ip}' is not a valid IPv4 or IPv6 address format."
        }), 400

    # Call analyze_ip from detection.risk_engine
    result = analyze_ip(ip)

    return jsonify({
        "status": "success",
        "data": result
    })


@app.route('/history')
def history():
    """Shows all previously searched IPs by querying SearchHistory from the database."""
    session = SessionLocal()
    try:
        # Query SearchHistory from database
        records = session.query(SearchHistory).order_by(SearchHistory.searched_at.desc()).all()
    finally:
        session.close()

    return render_template('history.html', history=records)


@app.route('/history/clear', methods=['POST'])
def clear_history():
    """Clear all historical search records from database."""
    session = SessionLocal()
    try:
        session.query(SearchHistory).delete()
        session.query(IPReport).delete()
        session.commit()
        flash("Search history has been cleared.", "info")
    except Exception as e:
        session.rollback()
        flash(f"Failed to clear history: {str(e)}", "error")
    finally:
        session.close()
    return redirect(url_for('history'))


@app.route('/api/local-ip')
def api_local_ip():
    """Returns local IP address of host system."""
    return jsonify({"status": "success", "ip": get_local_ip()})


@app.route('/scan')
@app.route('/scanner')
def scanner():
    """Scanner page for running deep port scan, CVE lookup, MITRE mapping, and AI analysis."""
    return render_template('scanner.html')


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """
    POST route accepting JSON with target_ip field.
    Runs nmap scan, parallel CVE lookup, MITRE technique mapping, AI analysis,
    and PDF report generation.
    """
    data = request.get_json(silent=True) or {}
    target_ip = data.get('target_ip', '').strip()

    # Validate IP address
    if not target_ip or not is_valid_ip(target_ip):
        return jsonify({
            "status": "error",
            "message": f"'{target_ip}' is not a valid IPv4 or IPv6 address format."
        }), 400

    # 1. Scan target using parser/nmap_scanner.py
    scan_results = scan_target(target_ip)
    open_ports = scan_results.get("open_ports", [])

    # 2. Parallel CVE lookup using ThreadPoolExecutor
    cve_results = {}

    def _fetch_cve(port_info):
        service = port_info.get("service_name", "")
        version = port_info.get("service_version", "")
        port = port_info.get("port", "")
        label = f"{service} {port}".strip() or f"port_{port}"
        if service:
            cves = get_cves_for_service(service, version)
        else:
            cves = []
        return label, cves

    if open_ports:
        with ThreadPoolExecutor(max_workers=min(10, len(open_ports))) as executor:
            cve_pairs = list(executor.map(_fetch_cve, open_ports))
            for label, cves in cve_pairs:
                cve_results[label] = cves

    # 3. MITRE ATT&CK mapping
    mitre_mappings = map_ports_to_mitre(open_ports)

    # 4. AI Security Analysis
    ai_analysis = analyze_with_ai(scan_results, cve_results, mitre_mappings)

    # 5. Generate PDF report in screenshots/ directory
    reports_dir = os.path.join(app.root_path, "screenshots")
    os.makedirs(reports_dir, exist_ok=True)
    safe_filename = f"report_{target_ip.replace(':', '_')}.pdf"
    output_pdf_path = os.path.join(reports_dir, safe_filename)

    generate_pdf_report(
        scan_data=scan_results,
        cve_data=cve_results,
        mitre_data=mitre_mappings,
        ai_analysis=ai_analysis,
        output_path=output_pdf_path
    )

    pdf_download_url = url_for('download_report', ip=target_ip)

    return jsonify({
        "status": "success",
        "pdf_url": pdf_download_url,
        "data": {
            "scan_results": scan_results,
            "cve_results": cve_results,
            "mitre_mappings": mitre_mappings,
            "ai_analysis": ai_analysis
        }
    })


@app.route('/download/report/<ip>')
def download_report(ip):
    """GET route serving the generated PDF report for download."""
    ip = ip.strip()
    if not is_valid_ip(ip):
        flash(f"'{ip}' is not a valid IPv4 or IPv6 address format.", "error")
        return redirect(url_for('home'))

    reports_dir = os.path.join(app.root_path, "screenshots")
    safe_filename = f"report_{ip.replace(':', '_')}.pdf"
    pdf_path = os.path.join(reports_dir, safe_filename)

    if not os.path.exists(pdf_path):
        flash(f"Report PDF for IP '{ip}' does not exist.", "error")
        return redirect(url_for('scanner'))

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f"Security_Report_{ip}.pdf",
        mimetype="application/pdf"
    )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
