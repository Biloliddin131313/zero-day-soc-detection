#!/usr/bin/env python3
"""
0xDay Zeek Bridge
Converts Zeek conn.log entries into CICIDS-compatible CSV rows
and appends them to a live CSV file that soc_exporter_v2.py reads.
"""
import os
import time
import math
import pandas as pd

ZEEK_LOG = os.path.expanduser("~/zeek-logs/conn.log")
OUTPUT_CSV = os.path.expanduser("~/zero-day-soc-detection/dataset/cicids2017/live_flows.csv")

# CICIDS column names (78 features + label)
COLUMNS = [
    " Destination Port", " Flow Duration", " Total Fwd Packets",
    " Total Backward Packets", "Total Length of Fwd Packets",
    " Total Length of Bwd Packets", " Fwd Packet Length Max",
    " Fwd Packet Length Min", " Fwd Packet Length Mean",
    " Fwd Packet Length Std", "Bwd Packet Length Max",
    " Bwd Packet Length Min", " Bwd Packet Length Mean",
    " Bwd Packet Length Std", "Flow Bytes/s", " Flow Packets/s",
    " Flow IAT Mean", " Flow IAT Std", " Flow IAT Max",
    " Flow IAT Min", "Fwd IAT Total", " Fwd IAT Mean",
    " Fwd IAT Std", " Fwd IAT Max", " Fwd IAT Min",
    "Bwd IAT Total", " Bwd IAT Mean", " Bwd IAT Std",
    " Bwd IAT Max", " Bwd IAT Min", "Fwd PSH Flags",
    " Bwd PSH Flags", " Fwd URG Flags", " Bwd URG Flags",
    " Fwd Header Length", " Bwd Header Length", "Fwd Packets/s",
    " Bwd Packets/s", " Min Packet Length", " Max Packet Length",
    " Packet Length Mean", " Packet Length Std", " Packet Length Variance",
    " FIN Flag Count", " SYN Flag Count", " RST Flag Count",
    " PSH Flag Count", " ACK Flag Count", " URG Flag Count",
    " CWE Flag Count", " ECE Flag Count", " Down/Up Ratio",
    " Average Packet Size", " Avg Fwd Segment Size",
    " Avg Bwd Segment Size", " Fwd Header Length.1", "Fwd Avg Bytes/Bulk",
    " Fwd Avg Packets/Bulk", " Fwd Avg Bulk Rate", " Bwd Avg Bytes/Bulk",
    " Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets",
    " Subflow Fwd Bytes", " Subflow Bwd Packets", " Subflow Bwd Bytes",
    "Init_Win_bytes_forward", " Init_Win_bytes_backward",
    " act_data_pkt_fwd", " min_seg_size_forward", "Active Mean",
    " Active Std", " Active Max", " Active Min", "Idle Mean",
    " Idle Std", " Idle Max", " Idle Min", " Label"
]

def zeek_to_cicids(row):
    """Convert a Zeek conn.log row to CICIDS feature vector."""
    try:
        fields = row.strip().split('\t')
        if len(fields) < 20 or fields[0].startswith('#'):
            return None

        dst_port   = int(fields[5]) if fields[5] != '-' else 0
        proto      = fields[6]
        duration   = float(fields[8]) * 1e6 if fields[8] != '-' else 0  # microseconds
        orig_bytes = int(fields[9]) if fields[9] != '-' else 0
        resp_bytes = int(fields[10]) if fields[10] != '-' else 0
        orig_pkts  = int(fields[16]) if fields[16] != '-' else 0
        orig_ip_bytes = int(fields[17]) if fields[17] != '-' else 0
        resp_pkts  = int(fields[18]) if fields[18] != '-' else 0
        resp_ip_bytes = int(fields[19]) if fields[19] != '-' else 0
        history    = fields[15] if fields[15] != '-' else ''

        total_pkts = orig_pkts + resp_pkts
        total_bytes = orig_bytes + resp_bytes
        dur_sec = duration / 1e6 if duration > 0 else 0.001

        # Flow rates
        flow_bytes_s = total_bytes / dur_sec if dur_sec > 0 else 0
        flow_pkts_s  = total_pkts / dur_sec if dur_sec > 0 else 0

        # Packet length estimates
        fwd_pkt_len = orig_bytes / orig_pkts if orig_pkts > 0 else 0
        bwd_pkt_len = resp_bytes / resp_pkts if resp_pkts > 0 else 0
        avg_pkt_len = total_bytes / total_pkts if total_pkts > 0 else 0

        # IAT estimates
        fwd_iat_mean = dur_sec / orig_pkts * 1e6 if orig_pkts > 0 else 0
        bwd_iat_mean = dur_sec / resp_pkts * 1e6 if resp_pkts > 0 else 0
        flow_iat_mean = dur_sec / total_pkts * 1e6 if total_pkts > 0 else 0

        # Flag detection from history string
        syn = 1 if 'S' in history else 0
        fin = 1 if 'F' in history else 0
        rst = 1 if 'R' in history else 0
        psh = 1 if 'P' in history else 0
        ack = 1 if 'A' in history else 0

        # Label based on port/behavior
        if dst_port == 80 and orig_pkts > 1000:
            label = "DDoS"
        elif dst_port == 22:
            label = "Brute Force"
        elif dst_port in [80, 8080, 5000] and 'P' in history:
            label = "Web Attack"
        elif orig_pkts > 500 and dst_port not in [80, 22, 443, 8001, 5000, 9090]:
            label = "DoS"
        else:
            label = "BENIGN"

        values = [
            dst_port, duration, orig_pkts, resp_pkts,
            orig_bytes, resp_bytes,
            fwd_pkt_len, 0, fwd_pkt_len, 0,
            bwd_pkt_len, 0, bwd_pkt_len, 0,
            flow_bytes_s, flow_pkts_s,
            flow_iat_mean, 0, flow_iat_mean*2, 0,
            dur_sec*1e6, fwd_iat_mean, 0, fwd_iat_mean*2, 0,
            dur_sec*1e6, bwd_iat_mean, 0, bwd_iat_mean*2, 0,
            psh, 0, 0, 0,
            orig_pkts*20, resp_pkts*20,
            flow_pkts_s/2, flow_pkts_s/2,
            0, max(fwd_pkt_len, bwd_pkt_len),
            avg_pkt_len, avg_pkt_len*0.1, avg_pkt_len*0.01,
            fin, syn, rst, psh, ack, 0, 0, 0,
            resp_pkts/(orig_pkts+1),
            avg_pkt_len, fwd_pkt_len, bwd_pkt_len,
            orig_pkts*20, 0, 0, 0, 0, 0, 0,
            orig_pkts, orig_bytes, resp_pkts, resp_bytes,
            orig_ip_bytes, resp_ip_bytes,
            orig_pkts, 20,
            0, 0, 0, 0,
            0, 0, 0, 0,
            label
        ]
        return values
    except Exception as e:
        return None

def main():
    print("0xDay Zeek Bridge starting...")
    print(f"Reading: {ZEEK_LOG}")
    print(f"Writing: {OUTPUT_CSV}")

    # Write CSV header
    with open(OUTPUT_CSV, 'w') as f:
        f.write(','.join(COLUMNS) + '\n')
    print("CSV header written")

    last_pos = 0
    batch = []
    batch_size = 100

    while True:
        try:
            if not os.path.exists(ZEEK_LOG):
                time.sleep(2)
                continue

            with open(ZEEK_LOG, 'r') as f:
                f.seek(last_pos)
                lines = f.readlines()
                last_pos = f.tell()

            for line in lines:
                if line.startswith('#'):
                    continue
                row = zeek_to_cicids(line)
                if row:
                    batch.append(row)

            if batch:
                df = pd.DataFrame(batch, columns=COLUMNS)
                df.to_csv(OUTPUT_CSV, mode='a', header=False, index=False)
                print(f"Wrote {len(batch)} flows to CSV")
                batch = []

        except Exception as e:
            print(f"Error: {e}")

        time.sleep(5)

if __name__ == "__main__":
    main()
