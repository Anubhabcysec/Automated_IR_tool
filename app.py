import json
import ipaddress
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from sqlalchemy.orm import sessionmaker

from config import Config
from database.models import SearchHistory, IPReport, create_tables
from detection.risk_engine import analyze_ip

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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
