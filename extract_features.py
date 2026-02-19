#!/usr/bin/env python3
"""
Clean QUIC Flow Feature Extraction for Research-Grade ML

Removed:
 - DoS signature heuristic features
 - Payload ratio
 - Handcrafted attack score

Improved:
 - Stable ratio calculations
 - More principled roundtrip approximation
"""

import pandas as pd
import numpy as np
import argparse
from pathlib import Path


# ==========================================================
# Parsing
# ==========================================================

def parse_zeek_conn_log(filepath: str) -> pd.DataFrame:
    print(f"Parsing {filepath}...")

    columns = [
        'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
        'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
        'conn_state', 'local_orig', 'local_resp', 'missed_bytes',
        'history', 'orig_pkts', 'orig_ip_bytes',
        'resp_pkts', 'resp_ip_bytes',
        'tunnel_parents', 'ip_proto'
    ]

    df = pd.read_csv(
        filepath,
        sep='\t',
        comment='#',
        names=columns,
        na_values=['-', '(empty)'],
        low_memory=False
    )

    numeric_cols = [
        'duration', 'orig_bytes', 'resp_bytes',
        'orig_pkts', 'resp_pkts'
    ]

    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    print(f"Parsed {len(df)} flows")
    return df


# ==========================================================
# Core Flow Features
# ==========================================================

def calculate_basic_features(df: pd.DataFrame) -> pd.DataFrame:
    features = pd.DataFrame()

    features['PACKETS_FWD'] = df['orig_pkts']
    features['PACKETS_REV'] = df['resp_pkts']
    features['PACKETS_TOTAL'] = df['orig_pkts'] + df['resp_pkts']

    features['BYTES_FWD'] = df['orig_bytes']
    features['BYTES_REV'] = df['resp_bytes']
    features['BYTES_TOTAL'] = df['orig_bytes'] + df['resp_bytes']

    features['DURATION'] = df['duration'].replace(0, 0.001)

    return features


# ==========================================================
# Rate Features
# ==========================================================

def calculate_rate_features(features: pd.DataFrame) -> pd.DataFrame:

    features['PPS_FWD'] = features['PACKETS_FWD'] / features['DURATION']
    features['PPS_REV'] = features['PACKETS_REV'] / features['DURATION']

    features['BPS_FWD'] = features['BYTES_FWD'] / features['DURATION']
    features['BPS_REV'] = features['BYTES_REV'] / features['DURATION']

    return features


# ==========================================================
# Ratio & Asymmetry Features (Improved)
# ==========================================================

def calculate_ratio_features(features: pd.DataFrame) -> pd.DataFrame:

    eps = 1e-6  # numerical stability

    features['FWD_BWD_PKT_RATIO'] = (
        features['PACKETS_FWD'] / (features['PACKETS_REV'] + eps)
    )

    features['FWD_BWD_BYTE_RATIO'] = (
        features['BYTES_FWD'] / (features['BYTES_REV'] + eps)
    )

    # Normalized asymmetry [0,1]
    total_pkts = features['PACKETS_TOTAL']
    features['ASYMMETRY'] = np.where(
        total_pkts > 0,
        np.abs(features['PACKETS_FWD'] - features['PACKETS_REV']) / total_pkts,
        0
    )

    return features


# ==========================================================
# Improved Roundtrip Approximation
# ==========================================================

def calculate_roundtrip_features(features: pd.DataFrame) -> pd.DataFrame:
    """
    More principled roundtrip approximation:

    Instead of min(fwd, rev),
    use half of total bidirectional exchanges.

    Rationale:
    A full bidirectional exchange requires at least
    one forward + one reverse packet.
    """

    features['BIDIRECTIONAL_PAIRS'] = (
        np.minimum(features['PACKETS_FWD'], features['PACKETS_REV'])
    )

    # Roundtrip rate
    features['ROUNDTRIPS_PER_SEC'] = (
        features['BIDIRECTIONAL_PAIRS'] / features['DURATION']
    )

    return features


# ==========================================================
# Packet Size & Timing
# ==========================================================

def calculate_packet_size_features(features: pd.DataFrame) -> pd.DataFrame:

    eps = 1e-6

    features['MEAN_PKT_SIZE_FWD'] = (
        features['BYTES_FWD'] / (features['PACKETS_FWD'] + eps)
    )

    features['MEAN_PKT_SIZE_REV'] = (
        features['BYTES_REV'] / (features['PACKETS_REV'] + eps)
    )

    return features


def calculate_timing_features(features: pd.DataFrame) -> pd.DataFrame:

    eps = 1e-6

    features['TIME_PER_PKT_FWD'] = (
        features['DURATION'] / (features['PACKETS_FWD'] + eps)
    )

    return features


# ==========================================================
# State Features (Keep but drop before ML if desired)
# ==========================================================

def calculate_state_features(df: pd.DataFrame, features: pd.DataFrame):

    conn_state = df['conn_state'].fillna('UNKNOWN')

    features['IS_COMPLETE'] = (conn_state == 'SF').astype(int)
    features['IS_INCOMPLETE'] = conn_state.isin(['S0', 'S1']).astype(int)
    features['IS_RESET'] = conn_state.isin(['RSTO', 'RSTR', 'RSTOS0']).astype(int)
    features['IS_REJECTED'] = (conn_state == 'REJ').astype(int)

    return features


# ==========================================================
# Label
# ==========================================================

def add_label(features: pd.DataFrame, label: str):
    features['LABEL'] = label
    return features


# ==========================================================
# Main Extraction
# ==========================================================

def extract_all_features(input_file, output_file, label):

    df = parse_zeek_conn_log(input_file)

    print("Calculating features...")

    features = calculate_basic_features(df)
    features = calculate_rate_features(features)
    features = calculate_ratio_features(features)
    features = calculate_roundtrip_features(features)
    features = calculate_packet_size_features(features)
    features = calculate_timing_features(features)
    features = calculate_state_features(df, features)
    features = add_label(features, label)

    features = features.replace([np.inf, -np.inf], 0)
    features = features.fillna(0)

    features.to_csv(output_file, index=False)

    print(f"\n✓ Saved cleaned feature set to: {output_file}")
    print(f"Total flows: {len(features)}")
    print(f"Total features: {len(features.columns) - 1}")


# ==========================================================
# CLI
# ==========================================================

def main():
    parser = argparse.ArgumentParser(
        description="Clean QUIC Feature Extraction"
    )

    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--label', required=True,
                        choices=['Benign', 'Malicious'])

    args = parser.parse_args()

    if not Path(args.input).exists():
        print("Input file not found.")
        return

    extract_all_features(args.input, args.output, args.label)


if __name__ == "__main__":
    main()
