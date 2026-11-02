"""
Sysmon Sentinel - Local Endpoint Monitoring Dashboard
=====================================================
Refactored Data Ingestion Pipeline & Telemetry Parser for Windows Sysmon.
Monitors: Applications and Services Logs -> Microsoft -> Windows -> Sysmon -> Operational

Key Enhancements:
1. Automated Noise Suppression: Drops collector polling loops (wevtutil, sc, conhost, app.py).
2. Complete Event ID 11 (File Create) extraction and metric mapping.
3. Clean process binary extraction with PID and abbreviated command paths.
4. Dynamic, context-aware "Key Details" generator for all common Sysmon event types.
5. Full telemetry binding: Parent-child hierarchy, parsed hashes, and raw XML payload.
"""

import os
import sys
import re
import json
import ctypes
import subprocess
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

# -----------------------------------------------------------------------------
# Sysmon Event ID Metadata & Categorization
# -----------------------------------------------------------------------------
SYSMON_EVENTS_METADATA = {
    1: {
        "name": "Process Create",
        "category": "Process",
        "severity": "info",
        "badge_class": "badge-process",
        "description": "Process created on the system"
    },
    2: {
        "name": "File Creation Time Changed",
        "category": "File",
        "severity": "low",
        "badge_class": "badge-file",
        "description": "A process changed a file creation time"
    },
    3: {
        "name": "Network Connection",
        "category": "Network",
        "severity": "info",
        "badge_class": "badge-network",
        "description": "TCP/UDP network connection detected"
    },
    4: {
        "name": "Sysmon Service State Changed",
        "category": "System",
        "severity": "high",
        "badge_class": "badge-system",
        "description": "Sysmon service status changed"
    },
    5: {
        "name": "Process Terminated",
        "category": "Process",
        "severity": "low",
        "badge_class": "badge-process",
        "description": "A process has stopped running"
    },
    6: {
        "name": "Driver Loaded",
        "category": "Driver",
        "severity": "medium",
        "badge_class": "badge-driver",
        "description": "Kernel driver loaded into memory"
    },
    7: {
        "name": "Image Loaded",
        "category": "Image",
        "severity": "low",
        "badge_class": "badge-image",
        "description": "DLL / Module loaded by a process"
    },
    8: {
        "name": "CreateRemoteThread",
        "category": "Injection",
        "severity": "critical",
        "badge_class": "badge-critical",
        "description": "Remote thread injection detected"
    },
    9: {
        "name": "RawAccessRead",
        "category": "Disk",
        "severity": "high",
        "badge_class": "badge-disk",
        "description": "Raw disk read access using \\\\.\\"
    },
    10: {
        "name": "ProcessAccess",
        "category": "Process",
        "severity": "medium",
        "badge_class": "badge-process",
        "description": "Process opened handle to another process"
    },
    11: {
        "name": "File Created",
        "category": "File",
        "severity": "info",
        "badge_class": "badge-file",
        "description": "File created or overwritten"
    },
    12: {
        "name": "Registry Object Create/Delete",
        "category": "Registry",
        "severity": "medium",
        "badge_class": "badge-registry",
        "description": "Registry key or object created or deleted"
    },
    13: {
        "name": "Registry Value Set",
        "category": "Registry",
        "severity": "medium",
        "badge_class": "badge-registry",
        "description": "Registry value created or modified"
    },
    14: {
        "name": "Registry Key/Value Rename",
        "category": "Registry",
        "severity": "medium",
        "badge_class": "badge-registry",
        "description": "Registry key or value renamed"
    },
    15: {
        "name": "File Create Stream Hash",
        "category": "File",
        "severity": "medium",
        "badge_class": "badge-file",
        "description": "Named stream created on a file"
    },
    16: {
        "name": "Sysmon Config Changed",
        "category": "System",
        "severity": "high",
        "badge_class": "badge-system",
        "description": "Sysmon configuration file reloaded"
    },
    17: {
        "name": "Pipe Created",
        "category": "IPC",
        "severity": "low",
        "badge_class": "badge-ipc",
        "description": "Named pipe created"
    },
    18: {
        "name": "Pipe Connected",
        "category": "IPC",
        "severity": "low",
        "badge_class": "badge-ipc",
        "description": "Named pipe connection opened"
    },
    19: {
        "name": "WmiEvent (Filter)",
        "category": "WMI",
        "severity": "high",
        "badge_class": "badge-wmi",
        "description": "WMI event filter activity"
    },
    20: {
        "name": "WmiEvent (Consumer)",
        "category": "WMI",
        "severity": "high",
        "badge_class": "badge-wmi",
        "description": "WMI event consumer activity"
    },
    21: {
        "name": "WmiEvent (ConsumerToFilter)",
        "category": "WMI",
        "severity": "high",
        "badge_class": "badge-wmi",
        "description": "WMI consumer to filter binding"
    },
    22: {
        "name": "DNS Query",
        "category": "Network",
        "severity": "info",
        "badge_class": "badge-dns",
        "description": "DNS query and response logged"
    },
    23: {
        "name": "File Delete Archived",
        "category": "File",
        "severity": "medium",
        "badge_class": "badge-file",
        "description": "File deleted and archived by Sysmon"
    },
    24: {
        "name": "Clipboard Change",
        "category": "Clipboard",
        "severity": "low",
        "badge_class": "badge-clipboard",
        "description": "Clipboard content captured"
    },
    25: {
        "name": "Process Tampering",
        "category": "Tampering",
        "severity": "critical",
        "badge_class": "badge-critical",
        "description": "Process image hollowing or tampering"
    },
    26: {
        "name": "File Delete Logged",
        "category": "File",
        "severity": "medium",
        "badge_class": "badge-file",
        "description": "File delete detected (no archive)"
    }
}


def check_is_elevated():
    """Check if the current process is running with Administrator elevation."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def check_sysmon_service():
    """Check if Sysmon / Sysmon64 service is installed and running."""
    service_status = {
        "installed": False,
        "running": False,
        "service_name": None,
        "display_name": None
    }
    for s_name in ["Sysmon64", "Sysmon"]:
        try:
            res = subprocess.run(
                ["sc.exe", "query", s_name],
                capture_output=True,
                text=True,
                timeout=3
            )
            if res.returncode == 0:
                service_status["installed"] = True
                service_status["service_name"] = s_name
                if "RUNNING" in res.stdout:
                    service_status["running"] = True
                    service_status["display_name"] = f"{s_name} (Active)"
                else:
                    service_status["display_name"] = f"{s_name} (Stopped)"
                break
        except Exception:
            continue
    return service_status


def get_event_meta(event_id):
    """Retrieve metadata descriptor for a given Sysmon Event ID."""
    try:
        eid_int = int(event_id)
        if eid_int in SYSMON_EVENTS_METADATA:
            return SYSMON_EVENTS_METADATA[eid_int]
    except (ValueError, TypeError):
        pass
    return {
        "name": f"Sysmon Event {event_id}",
        "category": "Other",
        "severity": "info",
        "badge_class": "badge-other",
        "description": "Standard Sysmon event"
    }


def extract_process_name(image_path, command_line=""):
    """
    Extracts a clean binary filename (e.g., 'notepad.exe', 'cmd.exe').
    Falls back to parsing the first token of CommandLine if Image is absent.
    """
    if image_path:
        clean = os.path.basename(image_path).strip()
        if clean:
            return clean

    if command_line:
        cmd = command_line.strip()
        if cmd.startswith('"'):
            end_quote = cmd.find('"', 1)
            if end_quote != -1:
                return os.path.basename(cmd[1:end_quote])
        tokens = cmd.split()
        if tokens:
            return os.path.basename(tokens[0])

    return "System"


def generate_key_details(event_id, data):
    """
    Dedicated context-aware generator for human-readable 'KEY DETAILS'.
    Formats precise operational descriptions according to Sysmon Event ID.
    """
    eid = event_id

    # Event ID 1: Process Create
    if eid == 1:
        cmd = (data.get("CommandLine") or data.get("Image") or "").strip()
        if len(cmd) > 90:
            cmd = cmd[:87] + "..."
        return f"Executed: {cmd}" if cmd else "Process started"

    # Event ID 2: File Creation Time Changed
    elif eid == 2:
        target = data.get("TargetFilename", "Unknown file")
        return f"File creation time modified: {target}"

    # Event ID 3: Network Connection
    elif eid == 3:
        dst_ip = data.get("DestinationIp", "0.0.0.0")
        dst_port = data.get("DestinationPort", "")
        dst_host = data.get("DestinationHostname", "")
        proto = (data.get("Protocol") or "tcp").upper()
        initiated = data.get("Initiated", "true").lower() == "true"
        direction = "Outbound connection to" if initiated else "Inbound connection from"

        host_info = f" ({dst_host})" if dst_host and dst_host != dst_ip else ""
        port_info = f":{dst_port}" if dst_port else ""
        return f"{direction} {dst_ip}{port_info}{host_info} via {proto}"

    # Event ID 4: Sysmon Service State
    elif eid == 4:
        state = data.get("State", "Status changed")
        return f"Sysmon service state: {state}"

    # Event ID 5: Process Terminate
    elif eid == 5:
        pid = data.get("ProcessId", "N/A")
        return f"Process terminated (PID {pid})"

    # Event ID 6: Driver Loaded
    elif eid == 6:
        driver = data.get("ImageLoaded", "Kernel Driver")
        signed = data.get("Signed", "N/A")
        return f"Loaded driver: {os.path.basename(driver)} | Signed: {signed}"

    # Event ID 7: Image Loaded (DLL)
    elif eid == 7:
        dll = data.get("ImageLoaded", "")
        dll_name = os.path.basename(dll) if dll else "Module"
        signed = data.get("Signed", "N/A")
        sig_status = data.get("SignatureStatus", "")
        sig_info = f" | Sig: {sig_status}" if sig_status and sig_status.lower() != "valid" else ""
        return f"Loaded DLL: {dll_name} | Signed: {signed}{sig_info}"

    # Event ID 8: CreateRemoteThread
    elif eid == 8:
        target_pid = data.get("TargetProcessId", "N/A")
        target_img = os.path.basename(data.get("TargetImage", "Process"))
        return f"Remote thread injected into {target_img} (PID {target_pid})"

    # Event ID 9: RawAccessRead
    elif eid == 9:
        device = data.get("Device", "\\\\.\\PhysicalDrive0")
        return f"Raw disk read on device: {device}"

    # Event ID 10: ProcessAccess
    elif eid == 10:
        target = os.path.basename(data.get("TargetImage", "Process"))
        access = data.get("GrantedAccess", "")
        return f"Opened handle to {target} (Access: {access})"

    # Event ID 11: File Created
    elif eid == 11:
        target = data.get("TargetFilename") or data.get("TargetFileName") or "Unknown file"
        return f"Created file: {target}"

    # Event ID 12 / 13 / 14: Registry Events
    elif eid in (12, 13, 14):
        ev_type = data.get("EventType", "Registry Event")
        target_obj = data.get("TargetObject", "")
        details = data.get("Details", "")
        if details:
            if len(details) > 40:
                details = details[:37] + "..."
            return f"{ev_type}: {target_obj} (Value: {details})"
        return f"{ev_type}: {target_obj}"

    # Event ID 15: File Create Stream Hash
    elif eid == 15:
        target = data.get("TargetFilename", "Stream")
        return f"File stream created: {target}"

    # Event ID 16: Sysmon Config Changed
    elif eid == 16:
        return "Sysmon configuration file reloaded"

    # Event ID 17 / 18: Named Pipe Events
    elif eid in (17, 18):
        pipe = data.get("PipeName", "")
        action = "Pipe created" if eid == 17 else "Pipe connected"
        return f"{action}: {pipe}"

    # Event ID 19 / 20 / 21: WMI Activity
    elif eid in (19, 20, 21):
        name = data.get("Name") or data.get("EventConsumer", "WMI Event")
        return f"WMI Activity: {name}"

    # Event ID 22: DNS Query
    elif eid == 22:
        query = data.get("QueryName", "Unknown domain")
        results = (data.get("QueryResults") or "").strip().rstrip(";")
        if results:
            if len(results) > 45:
                results = results[:42] + "..."
            return f"DNS query for {query} -> Resolved: {results}"
        status = data.get("QueryStatus", "")
        status_info = f" (Status: {status})" if status else ""
        return f"DNS query for {query}{status_info}"

    # Event ID 23: File Delete Archived
    elif eid == 23:
        target = data.get("TargetFilename", "")
        return f"File deleted & archived: {target}"

    # Event ID 24: Clipboard Change
    elif eid == 24:
        return "Clipboard content change captured"

    # Event ID 25: Process Tampering
    elif eid == 25:
        tamper_type = data.get("Type", "Process Tampering")
        return f"Process Tampering Alert: {tamper_type}"

    # Event ID 26: File Delete Logged
    elif eid == 26:
        target = data.get("TargetFilename", "")
        return f"File delete detected: {target}"

    # Fallback to key values
    for k in ("TargetFilename", "DestinationIp", "QueryName", "TargetObject", "CommandLine", "Image"):
        v = data.get(k)
        if v:
            if len(v) > 75:
                v = v[:72] + "..."
            return f"{k}: {v}"

    return "Sysmon operational event"


def parse_hashes_field(hashes_str):
    """Parses Sysmon Hashes string ('SHA256=...,MD5=...') into a structured dict."""
    hashes_dict = {}
    if not hashes_str:
        return hashes_dict

    parts = hashes_str.split(",")
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            hashes_dict[k.strip().upper()] = v.strip()
        elif len(p.strip()) == 64:
            hashes_dict["SHA256"] = p.strip()
        elif len(p.strip()) == 32:
            hashes_dict["MD5"] = p.strip()
    return hashes_dict


def is_collector_noise(event):
    """
    Silently drops internal polling and collector noise generated by:
    - wevtutil.exe (Sysmon event reader queries)
    - sc.exe (service query checks)
    - conhost.exe (console host wrappers spawned for wevtutil/sc)
    - python app.py collector loop
    """
    data = event.get("data", {})
    image = (event.get("image") or data.get("Image") or "").strip().lower().replace("/", "\\")
    pname = (event.get("process_name") or os.path.basename(image) or "").strip().lower()
    cmd = (event.get("command_line") or data.get("CommandLine") or "").strip().lower()
    parent_img = (event.get("parent_image") or data.get("ParentImage") or "").strip().lower().replace("/", "\\")
    parent_cmd = (event.get("parent_command_line") or data.get("ParentCommandLine") or "").strip().lower()

    # 1. Filter out wevtutil, sc, and conhost processes
    if pname in ("wevtutil.exe", "sc.exe", "conhost.exe") or image.endswith(("\\wevtutil.exe", "\\sc.exe", "\\conhost.exe")):
        return True

    # 2. Filter out commands querying Sysmon operational log or service status
    if "wevtutil" in cmd and "microsoft-windows-sysmon" in cmd:
        return True
    if "sc.exe query sysmon" in cmd or "sc query sysmon" in cmd:
        return True

    # 3. Filter out parent processes of wevtutil/sc
    if any(parent_img.endswith(f"\\{x}") for x in ("wevtutil.exe", "sc.exe")):
        return True
    if "wevtutil" in parent_cmd or "sc.exe query" in parent_cmd:
        return True

    # 4. Filter out telemetry calls originating from app.py itself
    if "app.py" in cmd and ("python" in cmd or "wevtutil" in cmd):
        return True

    # 5. ImageLoaded (Event ID 7) where the loading process is wevtutil or sc
    if event.get("event_id") == 7:
        if pname in ("wevtutil.exe", "sc.exe", "conhost.exe") or image.endswith(("\\wevtutil.exe", "\\sc.exe", "\\conhost.exe")):
            return True

    return False


def parse_sysmon_xml(xml_content):
    """
    Safely parses multi-event XML from wevtutil qe output into structured dictionaries.
    Uses regex to extract individual <Event>...</Event> blocks, preventing single-event
    syntax glitches from corrupting the entire batch.
    """
    parsed_events = []
    if not xml_content or not xml_content.strip():
        return parsed_events

    event_blocks = re.findall(r'<Event[\s>].*?</Event>', xml_content, re.DOTALL)

    for block in event_blocks:
        try:
            elem = ET.fromstring(block)
            sys_node = None
            event_data_node = None

            for child in elem:
                tag = child.tag.split("}")[-1]
                if tag == "System":
                    sys_node = child
                elif tag == "EventData":
                    event_data_node = child

            event_id = None
            timestamp = ""
            computer = ""
            record_id = ""
            channel = "Microsoft-Windows-Sysmon/Operational"
            provider = "Microsoft-Windows-Sysmon"

            if sys_node is not None:
                for c in sys_node:
                    ctag = c.tag.split("}")[-1]
                    if ctag == "EventID":
                        try:
                            event_id = int(c.text.strip())
                        except Exception:
                            event_id = c.text.strip() if c.text else None
                    elif ctag == "TimeCreated":
                        timestamp = c.attrib.get("SystemTime", "")
                    elif ctag == "Computer":
                        computer = c.text or ""
                    elif ctag == "EventRecordID":
                        record_id = c.text or ""
                    elif ctag == "Channel":
                        channel = c.text or channel
                    elif ctag == "Provider":
                        provider = c.attrib.get("Name", provider)

            # Parse EventData key-values
            data = {}
            if event_data_node is not None:
                for d in event_data_node:
                    name = d.attrib.get("Name")
                    if name:
                        data[name] = d.text if d.text is not None else ""

            # Extract fields
            image = data.get("Image", "")
            command_line = data.get("CommandLine", "")
            process_name = extract_process_name(image, command_line)
            user = data.get("User", "")
            process_id = data.get("ProcessId", "")

            parent_image = data.get("ParentImage", "")
            parent_command_line = data.get("ParentCommandLine", "")
            parent_process_name = extract_process_name(parent_image, parent_command_line)
            parent_process_id = data.get("ParentProcessId", "")

            # Network fields (Event ID 3)
            dest_ip = data.get("DestinationIp", "")
            dest_port = data.get("DestinationPort", "")
            dest_host = data.get("DestinationHostname", "")
            dest_port_name = data.get("DestinationPortName", "")
            protocol = data.get("Protocol", "")
            source_ip = data.get("SourceIp", "")
            source_port = data.get("SourcePort", "")

            # File fields (Event ID 11 / 2 / 23)
            target_filename = data.get("TargetFilename") or data.get("TargetFileName") or data.get("FileName") or ""
            creation_time = data.get("CreationUtcTime") or data.get("CreationTime") or ""

            # Registry fields (Event ID 12 / 13 / 14)
            target_object = data.get("TargetObject", "")
            registry_details = data.get("Details", "")

            # DNS fields (Event ID 22)
            query_name = data.get("QueryName", "")
            query_status = data.get("QueryStatus", "")
            query_results = data.get("QueryResults", "")

            # Hashes & Security
            hashes = data.get("Hashes", "")
            parsed_hashes = parse_hashes_field(hashes)
            integrity_level = data.get("IntegrityLevel", "")

            meta = get_event_meta(event_id)
            key_details = generate_key_details(event_id, data)

            parsed_events.append({
                "record_id": record_id,
                "event_id": event_id,
                "event_type": meta["name"],
                "category": meta["category"],
                "severity": meta["severity"],
                "badge_class": meta["badge_class"],
                "timestamp": timestamp,
                "computer": computer,
                "channel": channel,
                "provider": provider,
                "user": user,
                "image": image,
                "process_name": process_name,
                "process_id": process_id,
                "command_line": command_line,
                "parent_image": parent_image,
                "parent_process_name": parent_process_name,
                "parent_process_id": parent_process_id,
                "parent_command_line": parent_command_line,
                "destination_ip": dest_ip,
                "destination_port": dest_port,
                "destination_hostname": dest_host,
                "destination_port_name": dest_port_name,
                "protocol": protocol,
                "source_ip": source_ip,
                "source_port": source_port,
                "target_filename": target_filename,
                "creation_time": creation_time,
                "target_object": target_object,
                "registry_details": registry_details,
                "query_name": query_name,
                "query_status": query_status,
                "query_results": query_results,
                "hashes": hashes,
                "parsed_hashes": parsed_hashes,
                "integrity_level": integrity_level,
                "key_details": key_details,
                "data": data,
                "raw_xml": block,
                "is_demo": False
            })
        except Exception:
            continue

    return parsed_events


def generate_fallback_sample_events():
    """
    Generates realistic, noise-free fallback Sysmon events for testing
    or presentation when run without Administrator elevation.
    Every event is explicitly flagged with is_demo: True.
    """
    now = datetime.now(timezone.utc)
    base_ts = now.isoformat()

    sample_items = [
        {
            "event_id": 1,
            "data": {
                "Image": "C:\\Windows\\System32\\notepad.exe",
                "CommandLine": '"C:\\Windows\\System32\\notepad.exe" C:\\Users\\Admin\\Desktop\\hackathon_notes.txt',
                "ProcessId": "9428",
                "User": "DESKTOP-SEC01\\Admin",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "ParentCommandLine": "C:\\Windows\\Explorer.EXE",
                "ParentProcessId": "4120",
                "CurrentDirectory": "C:\\Users\\Admin\\Desktop\\",
                "IntegrityLevel": "Medium",
                "Hashes": "SHA256=3B9E138E165D9BE7B3A2209DB49C776BBEEB6A1DF8FF8DEB7B805FEBE723E2A2,MD5=69EE406987C4DA8D3AE18501FA040B81,IMPHASH=13809C8FE9027B9B8FF7899757D89163",
                "Description": "Notepad",
                "Product": "Microsoft® Windows® Operating System"
            }
        },
        {
            "event_id": 11,
            "data": {
                "Image": "C:\\Windows\\System32\\notepad.exe",
                "ProcessId": "9428",
                "User": "DESKTOP-SEC01\\Admin",
                "TargetFilename": "C:\\Users\\Admin\\Desktop\\hackathon_notes.txt",
                "CreationUtcTime": base_ts,
                "RuleName": "TextFile_Creation"
            }
        },
        {
            "event_id": 22,
            "data": {
                "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "ProcessId": "7320",
                "User": "DESKTOP-SEC01\\Admin",
                "QueryName": "api.github.com",
                "QueryStatus": "0",
                "QueryResults": "140.82.121.6;",
                "RuleName": "DNS_GitHub"
            }
        },
        {
            "event_id": 3,
            "data": {
                "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "ProcessId": "7320",
                "User": "DESKTOP-SEC01\\Admin",
                "Protocol": "tcp",
                "Initiated": "true",
                "SourceIp": "192.168.1.105",
                "SourcePort": "54892",
                "DestinationIp": "140.82.121.6",
                "DestinationHostname": "api.github.com",
                "DestinationPort": "443",
                "DestinationPortName": "https"
            }
        },
        {
            "event_id": 1,
            "data": {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": 'powershell.exe -ExecutionPolicy Bypass -File .\\security_audit.ps1',
                "ProcessId": "8120",
                "User": "DESKTOP-SEC01\\Admin",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "ParentCommandLine": "C:\\Windows\\Explorer.EXE",
                "ParentProcessId": "4120",
                "CurrentDirectory": "C:\\Security\\",
                "IntegrityLevel": "High",
                "Hashes": "SHA256=A48FE091BC884321EF9810456104214589218540912401824081024810248120,MD5=84019284019284019284019284019284"
            }
        },
        {
            "event_id": 13,
            "data": {
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "ProcessId": "1340",
                "User": "NT AUTHORITY\\SYSTEM",
                "EventType": "SetValue",
                "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityAgent",
                "Details": "C:\\Program Files\\Security\\agent.exe",
                "RuleName": "Persistence_RunKey"
            }
        },
        {
            "event_id": 7,
            "data": {
                "Image": "C:\\Windows\\System32\\notepad.exe",
                "ImageLoaded": "C:\\Windows\\System32\\comctl32.dll",
                "ProcessId": "9428",
                "User": "DESKTOP-SEC01\\Admin",
                "Signed": "true",
                "Signature": "Microsoft Windows",
                "SignatureStatus": "Valid",
                "Hashes": "SHA256=4C12E3B294821049182401824091824091820491820491820491820491820491"
            }
        },
        {
            "event_id": 5,
            "data": {
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "ProcessId": "10844",
                "User": "DESKTOP-SEC01\\Admin"
            }
        }
    ]

    events = []
    for idx, item in enumerate(sample_items):
        eid = item["event_id"]
        meta = get_event_meta(eid)
        d = item["data"]
        img = d.get("Image", "")
        p_img = d.get("ParentImage", "")
        cmd = d.get("CommandLine", "")
        p_cmd = d.get("ParentCommandLine", "")
        hashes = d.get("Hashes", "")
        parsed_h = parse_hashes_field(hashes)
        key_det = generate_key_details(eid, d)

        events.append({
            "record_id": f"DEMO-{1001 + idx}",
            "event_id": eid,
            "event_type": meta["name"],
            "category": meta["category"],
            "severity": meta["severity"],
            "badge_class": meta["badge_class"],
            "timestamp": base_ts,
            "computer": "DESKTOP-SEC01 (Sample)",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "provider": "Microsoft-Windows-Sysmon",
            "user": d.get("User", ""),
            "image": img,
            "process_name": extract_process_name(img, cmd),
            "process_id": d.get("ProcessId", ""),
            "command_line": cmd,
            "parent_image": p_img,
            "parent_process_name": extract_process_name(p_img, p_cmd),
            "parent_process_id": d.get("ParentProcessId", ""),
            "parent_command_line": p_cmd,
            "destination_ip": d.get("DestinationIp", ""),
            "destination_port": d.get("DestinationPort", ""),
            "destination_hostname": d.get("DestinationHostname", ""),
            "destination_port_name": d.get("DestinationPortName", ""),
            "protocol": d.get("Protocol", ""),
            "source_ip": d.get("SourceIp", ""),
            "source_port": d.get("SourcePort", ""),
            "target_filename": d.get("TargetFilename", ""),
            "creation_time": d.get("CreationUtcTime", ""),
            "target_object": d.get("TargetObject", ""),
            "registry_details": d.get("Details", ""),
            "query_name": d.get("QueryName", ""),
            "query_status": d.get("QueryStatus", ""),
            "query_results": d.get("QueryResults", ""),
            "hashes": hashes,
            "parsed_hashes": parsed_h,
            "integrity_level": d.get("IntegrityLevel", ""),
            "key_details": key_det,
            "data": d,
            "raw_xml": f"<!-- DEMO SAMPLE EVENT #{idx + 1} -->\n<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>\n  <System>\n    <EventID>{eid}</EventID>\n    <TimeCreated SystemTime='{base_ts}'/>\n    <Computer>DESKTOP-SEC01</Computer>\n  </System>\n  <EventData>\n" + "".join([f"    <Data Name='{k}'>{v}</Data>\n" for k, v in d.items()]) + "  </EventData>\n</Event>",
            "is_demo": True
        })

    return events


def calculate_metrics(events):
    """
    Calculates live dashboard counters based strictly on clean retrieved events.
    Internal collector events are excluded prior to calculation.
    """
    stats = {
        "total": len(events),
        "process_create": 0,
        "network": 0,
        "file_create": 0,
        "dns": 0,
        "registry": 0,
        "other": 0,
        "unique_processes": set(),
        "high_severity": 0
    }

    for ev in events:
        eid = ev.get("event_id")
        pname = ev.get("process_name")
        if pname and pname != "System":
            stats["unique_processes"].add(pname.lower())

        if ev.get("severity") in ("high", "critical"):
            stats["high_severity"] += 1

        if eid == 1:
            stats["process_create"] += 1
        elif eid == 3:
            stats["network"] += 1
        elif eid == 11:
            stats["file_create"] += 1
        elif eid == 22:
            stats["dns"] += 1
        elif eid in (12, 13, 14):
            stats["registry"] += 1
        else:
            stats["other"] += 1

    stats["unique_processes_count"] = len(stats["unique_processes"])
    del stats["unique_processes"]
    return stats


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    """Renders the main Sysmon Sentinel monitoring dashboard."""
    is_elevated = check_is_elevated()
    svc = check_sysmon_service()
    return render_template(
        "index.html",
        is_elevated=is_elevated,
        sysmon_installed=svc["installed"],
        sysmon_running=svc["running"]
    )


@app.route("/api/status")
def api_status():
    """Returns endpoint diagnostics and Sysmon service status."""
    is_elevated = check_is_elevated()
    svc = check_sysmon_service()
    return jsonify({
        "status": "ok",
        "is_elevated": is_elevated,
        "sysmon_service": svc,
        "server_time": datetime.now().isoformat(),
        "os": "Windows"
    })


@app.route("/api/events")
def api_events():
    """
    Main API endpoint to retrieve Sysmon events.
    Supports:
        ?limit=100 (default 100, clamped between 10 and 1000)
        ?source=auto|live|demo (default auto)
    """
    limit = request.args.get("limit", default=100, type=int)
    limit = max(10, min(limit, 1000))
    source_pref = request.args.get("source", default="auto").lower()

    if source_pref == "demo":
        events = generate_fallback_sample_events()
        return jsonify({
            "status": "ok",
            "source": "demo",
            "is_demo_fallback": True,
            "total": len(events),
            "stats": calculate_metrics(events),
            "events": events,
            "message": "Displaying labeled demo fallback events."
        })

    # Query a larger buffer so that after dropping internal collector noise,
    # the client receives the requested limit of clean events
    query_count = max(limit * 3, 200)

    wevtutil_cmd = [
        "wevtutil.exe",
        "qe",
        "Microsoft-Windows-Sysmon/Operational",
        f"/c:{query_count}",
        "/rd:true",
        "/f:xml"
    ]

    try:
        proc = subprocess.run(
            wevtutil_cmd,
            capture_output=True,
            text=True,
            timeout=8
        )

        if proc.returncode == 0:
            raw_events = parse_sysmon_xml(proc.stdout)

            # Silently drop internal collector noise (wevtutil, sc, conhost, app.py)
            clean_events = [ev for ev in raw_events if not is_collector_noise(ev)]

            # Clamp to requested limit
            events = clean_events[:limit]
            stats = calculate_metrics(events)

            return jsonify({
                "status": "ok",
                "source": "live",
                "is_demo_fallback": False,
                "total": len(events),
                "stats": stats,
                "events": events,
                "message": f"Successfully retrieved {len(events)} live Sysmon events (collector noise suppressed)."
            })
        else:
            err_text = (proc.stderr or proc.stdout or "").strip()
            is_access_denied = "Access is denied" in err_text or proc.returncode == 5
            is_channel_missing = "channel" in err_text.lower() or "not found" in err_text.lower()

            troubleshooting = []
            if is_access_denied:
                troubleshooting = [
                    "Windows Event Log DACL restricts Microsoft-Windows-Sysmon/Operational to elevated administrators.",
                    "Close this window and open PowerShell or Command Prompt with 'Run as administrator'.",
                    "Navigate to this directory and start the app again: python app.py",
                    "Alternatively, grant permanent non-admin read access: net localgroup \"Event Log Readers\" $env:USERNAME /add (then re-login)."
                ]
            elif is_channel_missing:
                troubleshooting = [
                    "The Sysmon channel 'Microsoft-Windows-Sysmon/Operational' was not found.",
                    "Verify that Sysmon is installed: sysmon.exe -i or sysmon64.exe -i",
                    "Check if the Sysmon service is running: sc.exe query Sysmon64"
                ]
            else:
                troubleshooting = [
                    f"wevtutil exited with code {proc.returncode}.",
                    "Check Windows Event Viewer (eventvwr.msc) -> Applications and Services Logs -> Microsoft -> Windows -> Sysmon."
                ]

            if source_pref == "live":
                return jsonify({
                    "status": "error",
                    "source": "live",
                    "error_code": proc.returncode,
                    "error_message": err_text or "Failed to query Sysmon Operational event log.",
                    "troubleshooting": troubleshooting,
                    "events": [],
                    "stats": calculate_metrics([])
                }), 403 if is_access_denied else 500

            # Default auto: Return fallback data with clear notification and troubleshooting instructions
            fallback_events = generate_fallback_sample_events()
            return jsonify({
                "status": "permission_required" if is_access_denied else "log_error",
                "source": "demo_fallback",
                "is_demo_fallback": True,
                "error_message": err_text or "Access denied to Sysmon Operational event log (Run as Administrator required).",
                "troubleshooting": troubleshooting,
                "total": len(fallback_events),
                "stats": calculate_metrics(fallback_events),
                "events": fallback_events,
                "message": "Live Sysmon log query blocked by Windows permissions. Displaying labeled demo fallback data with troubleshooting instructions."
            })

    except subprocess.TimeoutExpired:
        return jsonify({
            "status": "error",
            "source": "live",
            "error_message": "Query to Windows Event Log timed out after 8 seconds.",
            "troubleshooting": ["The Sysmon log file might be under heavy write lock or system load."],
            "events": [],
            "stats": calculate_metrics([])
        }), 504
    except Exception as ex:
        return jsonify({
            "status": "error",
            "source": "unknown",
            "error_message": str(ex),
            "troubleshooting": ["Verify Python 3.11 environment and execution permissions."],
            "events": [],
            "stats": calculate_metrics([])
        }), 500


if __name__ == "__main__":
    is_admin = check_is_elevated()
    svc = check_sysmon_service()

    print("\n" + "=" * 70)
    print("  SYS-MON SENTINEL - LOCAL ENDPOINT MONITORING DASHBOARD")
    print("=" * 70)
    print("  * Local URL:           http://127.0.0.1:5000")
    print(f"  * Process Elevation:   {'[ELEVATED - FULL ACCESS]' if is_admin else '[STANDARD - ACCESS RESTRICTED]'}")
    print(f"  * Sysmon Service:      {svc.get('display_name', 'Not Detected')}")
    print("  * Target Event Log:    Microsoft-Windows-Sysmon/Operational")
    print("  * Collector Filter:    [ACTIVE] Suppressing internal wevtutil/sc/conhost noise")
    if not is_admin:
        print("\n  [!] TIP FOR LIVE EVENTS:")
        print("      To stream live Sysmon events, start your terminal with:")
        print("      'Run as administrator' -> python app.py")
        print("      Otherwise, the dashboard will offer labeled Demo Fallback data.")
    print("=" * 70 + "\n")

    # Strictly bind to 127.0.0.1 for local isolation
    app.run(host="127.0.0.1", port=5000, debug=False)
