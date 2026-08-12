"""
detection/mitre_mapper.py
-------------------------
Maps network observables (open ports, detected services, etc.) to MITRE
ATT&CK techniques and tactics.

Functions:
    map_ports_to_mitre(open_ports) -- Map a list of open-port dicts to ATT&CK
                                      technique entries.
"""

# ---------------------------------------------------------------------------
# Port → MITRE ATT&CK technique lookup table
# ---------------------------------------------------------------------------
# Each entry maps a specific port number to a fully described technique.
# Ports not listed here fall back to T1046 (Network Service Discovery).

_PORT_TECHNIQUE_MAP: dict = {
    21: {
        "technique_id": "T1021.001",
        "technique_name": "Remote Services: FTP",
        "tactic": "Lateral Movement",
    },
    22: {
        "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
    },
    23: {
        "technique_id": "T1021.005",
        "technique_name": "Remote Services: Telnet",
        "tactic": "Lateral Movement",
    },
    80: {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    443: {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    445: {
        "technique_id": "T1021.002",
        "technique_name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
    },
    3306: {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
    },
    3389: {
        "technique_id": "T1021.001",
        "technique_name": "Remote Services: RDP",
        "tactic": "Lateral Movement",
    },
}

# Fallback technique applied to any port not in the map above
_DEFAULT_TECHNIQUE: dict = {
    "technique_id": "T1046",
    "technique_name": "Network Service Discovery",
    "tactic": "Discovery",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def map_ports_to_mitre(open_ports: list) -> list:
    """
    Map a list of open-port dicts to MITRE ATT&CK techniques.

    Each element in *open_ports* should be a dict as returned by
    ``parser.nmap_scanner.scan_target()``, i.e. containing at least a
    ``"port"`` key with an integer port number.  Extra keys (protocol,
    service_name, etc.) are ignored but preserved via pass-through.

    Args:
        open_ports: List of dicts with at minimum ``{"port": <int>, ...}``.

    Returns:
        A list of dicts, one per input port, each containing:
            - port             (int)  The port number.
            - technique_id     (str)  ATT&CK technique ID  (e.g. "T1021.004").
            - technique_name   (str)  Human-readable technique name.
            - tactic           (str)  ATT&CK tactic name  (e.g. "Lateral Movement").

    Example::

        >>> ports = [{"port": 22, "protocol": "tcp", "state": "open", ...}]
        >>> map_ports_to_mitre(ports)
        [{"port": 22, "technique_id": "T1021.004",
          "technique_name": "Remote Services: SSH", "tactic": "Lateral Movement"}]
    """
    results = []

    for port_info in open_ports:
        port_number = port_info.get("port")

        if port_number is None:
            # Malformed entry — skip silently
            continue

        technique = _PORT_TECHNIQUE_MAP.get(port_number, _DEFAULT_TECHNIQUE)

        results.append(
            {
                "port": port_number,
                "technique_id": technique["technique_id"],
                "technique_name": technique["technique_name"],
                "tactic": technique["tactic"],
            }
        )

    return results
