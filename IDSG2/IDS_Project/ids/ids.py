#!/usr/bin/env python3
"""
ids_live.py - real-time flow-based IDS demo

Requirements:
 - scapy
 - joblib (for loading model and scaler)
Run with sudo/root privileges:
 $ sudo python3 ids_live.py
"""

import time
import threading
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, Raw
import joblib
import numpy as np
import logging

# --- Configuration ---
MODEL_PATH = "model.pkl"
SCALER_PATH = "scaler.pkl"
FLOW_TIMEOUT = 2.0       # seconds of inactivity before classifying a flow
CLASSIFY_EVERY = 1.0     # poll interval to check flows
LOG_FILE = "ids_live.log"

# Feature order MUST match features used during model training
FEATURE_ORDER = [
    "duration",       # seconds
    "total_bytes",
    "packet_count",
    "avg_pkt_len",
    "src_port",
    "dst_port",
    "protocol",       # numeric (e.g., 6 for TCP, 17 for UDP)
    "syn_count",
    "ack_count",
    "fin_count",
]

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger("").addHandler(console)

# Load model and scaler
try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    logging.info("Loaded model and scaler.")
except Exception as e:
    logging.error("Failed to load model/scaler: %s", e)
    raise SystemExit("Place trained model.pkl and scaler.pkl in project folder.")

# Data structure to keep active flows
# key -> dict with flow stats
flows = {}
flows_lock = threading.Lock()

def make_flow_key(pkt):
    """
    5-tuple flow key: (src, dst, sport, dport, proto)
    Use string normalized key to keep dict simple.
    """
    if IP not in pkt:
        return None
    ip = pkt[IP]
    proto = ip.proto
    src = ip.src
    dst = ip.dst
    sport = None
    dport = None
    if proto == 6 and TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif proto == 17 and UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
    else:
        sport = 0
        dport = 0
    return f"{src}:{sport}-{dst}:{dport}-{proto}"

def update_flow_with_packet(flow, pkt, ts):
    """
    Update the flow dict in-place with this packet information.
    """
    pkt_len = len(pkt)
    flow['last_ts'] = ts
    flow['packet_count'] += 1
    flow['total_bytes'] += pkt_len
    # Update first_ts if not set
    if flow['first_ts'] is None:
        flow['first_ts'] = ts
    # avg pkt len will be computed at classification
    # extract TCP flags counts if TCP
    if TCP in pkt:
        flags = pkt[TCP].flags
        # scapy represents flags as integer or characters depending; use bit checks
        # SYN = 0x02, ACK = 0x10, FIN = 0x01
        if flags & 0x02:
            flow['syn_count'] += 1
        if flags & 0x10:
            flow['ack_count'] += 1
        if flags & 0x01:
            flow['fin_count'] += 1

def packet_handler(pkt):
    ts = time.time()
    key = make_flow_key(pkt)
    if key is None:
        return

    with flows_lock:
        if key not in flows:
            # initialize
            flows[key] = {
                'first_ts': None,
                'last_ts': ts,
                'packet_count': 0,
                'total_bytes': 0,
                'src_port': 0,
                'dst_port': 0,
                'protocol': 0,
                'syn_count': 0,
                'ack_count': 0,
                'fin_count': 0,
            }
            # set ports/proto from packet
            try:
                if IP in pkt:
                    ip = pkt[IP]
                    flows[key]['protocol'] = ip.proto
                if TCP in pkt:
                    flows[key]['src_port'] = int(pkt[TCP].sport)
                    flows[key]['dst_port'] = int(pkt[TCP].dport)
                elif UDP in pkt:
                    flows[key]['src_port'] = int(pkt[UDP].sport)
                    flows[key]['dst_port'] = int(pkt[UDP].dport)
            except Exception:
                pass

        update_flow_with_packet(flows[key], pkt, ts)

def classify_flow(key, flow):
    """
    Build feature vector in the same order as FEATURE_ORDER,
    scale it, and predict using the loaded model.
    """
    duration = max(0.000001, flow['last_ts'] - (flow['first_ts'] or flow['last_ts']))
    total_bytes = flow['total_bytes']
    pkt_count = flow['packet_count']
    avg_pkt_len = total_bytes / pkt_count if pkt_count > 0 else 0

    fv = [
        duration,
        total_bytes,
        pkt_count,
        avg_pkt_len,
        flow.get('src_port', 0),
        flow.get('dst_port', 0),
        flow.get('protocol', 0),
        flow.get('syn_count', 0),
        flow.get('ack_count', 0),
        flow.get('fin_count', 0),
    ]

    # ensure shape (1, n)
    X = np.array(fv).reshape(1, -1)

    try:
        X_scaled = scaler.transform(X)
    except Exception as e:
        logging.error("Scaler transform failed: %s", e)
        X_scaled = X  # fallback: try raw features

    pred = model.predict(X_scaled)
    # If classifier supports predict_proba
    proba = None
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X_scaled).max()

    return pred[0], float(proba) if proba is not None else None, fv

def flow_monitor_loop():
    """
    Periodically check flows for inactivity and classify them.
    """
    while True:
        now = time.time()
        to_classify = []
        with flows_lock:
            for key, flow in list(flows.items()):
                if now - flow['last_ts'] > FLOW_TIMEOUT:
                    to_classify.append((key, flow.copy()))
                    # remove from active flows
                    del flows[key]
        # classify outside lock
        for key, flow in to_classify:
            try:
                label, confidence, fv = classify_flow(key, flow)
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                msg = f"{ts} | Flow {key} => Label: {label} | Conf: {confidence} | Features: {fv}"
                if str(label).lower() in ("attack", "malicious", "1", "true"):
                    logging.warning(msg)
                else:
                    logging.info(msg)
            except Exception as e:
                logging.error("Error classifying flow %s: %s", key, e)
        time.sleep(CLASSIFY_EVERY)

def main():
    logging.info("Starting flow monitor thread...")
    monitor_thread = threading.Thread(target=flow_monitor_loop, daemon=True)
    monitor_thread.start()

    logging.info("Starting packet sniffing (press Ctrl+C to stop)...")
    try:
        # sniff on all interfaces; change iface param to restrict
        sniff(prn=packet_handler, store=False)
    except KeyboardInterrupt:
        logging.info("Stopping sniffing. Exiting.")
    except Exception as e:
        logging.error("Sniffing failed: %s", e)

if __name__ == "__main__":
    main()
