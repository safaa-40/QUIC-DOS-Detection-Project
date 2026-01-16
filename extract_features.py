#!/usr/bin/env python3
"""
Advanced QUIC Flow Feature Extraction
Extracts comprehensive features for DoS detection with autoencoders
"""

import pandas as pd
import numpy as np
import argparse
from pathlib import Path


def parse_zeek_conn_log(filepath: str) -> pd.DataFrame:
    """Parse Zeek conn.log file"""
    
    print(f"Parsing {filepath}...")
    
    # Zeek conn.log column names (22 columns - includes ip_proto)
    columns = [
        'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
        'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
        'conn_state', 'local_orig', 'local_resp', 'missed_bytes',
        'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
        'tunnel_parents', 'ip_proto'
    ]
    
    # Read log file (skip comments)
    df = pd.read_csv(
        filepath,
        sep='\t',
        comment='#',
        names=columns,
        na_values=['-', '(empty)'],
        low_memory=False
    )
    
    # Force numeric conversion for key columns
    numeric_cols = ['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 
                   'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes']
    
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    
    print(f"Parsed {len(df)} flows")
    return df


def calculate_basic_features(df: pd.DataFrame) -> pd.DataFrame:
    """Calculate basic flow features"""
    
    features = pd.DataFrame()
    
    # Packet counts
    features['PACKETS'] = df['orig_pkts'].fillna(0)
    features['PACKETS_REV'] = df['resp_pkts'].fillna(0)
    features['PACKETS_TOTAL'] = features['PACKETS'] + features['PACKETS_REV']
    
    # Byte counts
    features['BYTES'] = df['orig_bytes'].fillna(0)
    features['BYTES_REV'] = df['resp_bytes'].fillna(0)
    features['BYTES_TOTAL'] = features['BYTES'] + features['BYTES_REV']
    
    # Duration
    features['DURATION'] = df['duration'].fillna(0.001)  # Avoid division by zero
    features['DURATION'] = features['DURATION'].replace(0, 0.001)
    
    return features


def calculate_rate_features(features: pd.DataFrame) -> pd.DataFrame:
    """Calculate rate-based features"""
    
    # Packets per second
    features['PPI'] = features['PACKETS'] / features['DURATION']
    features['PPI_REV'] = features['PACKETS_REV'] / features['DURATION']
    
    # Bytes per second
    features['BPS'] = features['BYTES'] / features['DURATION']
    features['BPS_REV'] = features['BYTES_REV'] / features['DURATION']
    
    return features


def calculate_ratio_features(features: pd.DataFrame) -> pd.DataFrame:
    """Calculate directional ratio features"""
    
    # Forward/Backward packet ratio
    features['FWD_BWD_PKT_RATIO'] = np.where(
        features['PACKETS_REV'] > 0,
        features['PACKETS'] / features['PACKETS_REV'],
        features['PACKETS']  # If no reverse, ratio = forward packets
    )
    
    # Forward/Backward byte ratio
    features['FWD_BWD_BYTE_RATIO'] = np.where(
        features['BYTES_REV'] > 0,
        features['BYTES'] / features['BYTES_REV'],
        features['BYTES']
    )
    
    # Asymmetry score (0 = symmetric, 1 = completely asymmetric)
    max_pkts = np.maximum(features['PACKETS'], features['PACKETS_REV'])
    features['ASYMMETRY_SCORE'] = np.where(
        max_pkts > 0,
        np.abs(features['PACKETS'] - features['PACKETS_REV']) / max_pkts,
        0
    )
    
    return features


def calculate_packet_size_features(features: pd.DataFrame) -> pd.DataFrame:
    """Calculate packet size statistics"""
    
    # Average packet sizes
    features['PKT_SIZE_MEAN'] = np.where(
        features['PACKETS'] > 0,
        features['BYTES'] / features['PACKETS'],
        0
    )
    
    features['PKT_SIZE_MEAN_REV'] = np.where(
        features['PACKETS_REV'] > 0,
        features['BYTES_REV'] / features['PACKETS_REV'],
        0
    )
    
    # Note: Min, max, std require per-packet data (not available in conn.log)
    # These would need packet-level pcap analysis
    
    return features


def calculate_timing_features(features: pd.DataFrame) -> pd.DataFrame:
    """Calculate timing-based features"""
    
    # Average time per packet
    features['TIME_PER_PKT'] = np.where(
        features['PACKETS'] > 0,
        features['DURATION'] / features['PACKETS'],
        0
    )
    
    # Note: IAT statistics require packet timestamps (not in conn.log)
    # Would need packet-level analysis
    
    return features


def calculate_bidirectional_features(features: pd.DataFrame) -> pd.DataFrame:
    """Calculate bidirectional interaction features"""
    
    # Roundtrips (minimum of forward and reverse packets)
    features['ROUNDTRIPS'] = np.minimum(
        features['PACKETS'],
        features['PACKETS_REV']
    )
    
    # Roundtrips per second
    features['ROUNDTRIPS_PER_SEC'] = features['ROUNDTRIPS'] / features['DURATION']
    
    return features


def calculate_state_features(df: pd.DataFrame, features: pd.DataFrame) -> pd.DataFrame:
    """Calculate connection state features"""
    
    conn_state = df['conn_state'].fillna('UNKNOWN')
    
    # Flow end reason (following CESNET-QUIC22 format)
    # IDLE: Connection attempt but no proper termination
    idle_states = ['S0', 'S1', 'SH', 'S2', 'S3', 'RSTOS0']
    features['FLOW_ENDREASON_IDLE'] = conn_state.isin(idle_states).astype(int)
    
    # ACTIVE: Normal establishment and termination
    features['FLOW_ENDREASON_ACTIVE'] = (conn_state == 'SF').astype(int)
    
    # OTHER: Abnormal termination
    other_states = ['RSTO', 'RSTR', 'REJ', 'OTH', 'UNKNOWN']
    features['FLOW_ENDREASON_OTHER'] = conn_state.isin(other_states).astype(int)
    
    # Binary flags
    features['IS_COMPLETE'] = (conn_state == 'SF').astype(int)
    features['IS_INCOMPLETE'] = conn_state.isin(['S0', 'S1']).astype(int)
    features['IS_RESET'] = conn_state.isin(['RSTO', 'RSTR', 'RSTOS0']).astype(int)
    features['IS_REJECTED'] = (conn_state == 'REJ').astype(int)
    
    return features


def calculate_dos_signature_features(features: pd.DataFrame) -> pd.DataFrame:
    """Calculate DoS attack signature features"""
    
    # Short-lived connections (< 1 second)
    features['SHORT_LIVED'] = (features['DURATION'] < 1.0).astype(int)
    
    # No response from server
    features['NO_RESPONSE'] = (features['PACKETS_REV'] == 0).astype(int)
    
    # Very few responses (< 3 packets)
    features['FEW_RESPONSES'] = (features['PACKETS_REV'] < 3).astype(int)
    
    # High packet rate (> 100 packets/sec)
    features['HIGH_RATE'] = (features['PPI'] > 100).astype(int)
    
    # Extremely high rate (> 500 packets/sec)
    features['VERY_HIGH_RATE'] = (features['PPI'] > 500).astype(int)
    
    # Asymmetric communication (forward >> backward)
    features['HIGHLY_ASYMMETRIC'] = (features['FWD_BWD_PKT_RATIO'] > 10).astype(int)
    
    # Incomplete handshake with no data
    features['INCOMPLETE_NO_DATA'] = (
        (features['IS_INCOMPLETE'] == 1) &
        (features['BYTES_REV'] == 0)
    ).astype(int)
    
    # DoS score (weighted combination)
    features['DOS_SCORE'] = (
        0.25 * features['SHORT_LIVED'] +
        0.20 * features['NO_RESPONSE'] +
        0.15 * features['IS_INCOMPLETE'] +
        0.15 * features['HIGH_RATE'] +
        0.15 * features['HIGHLY_ASYMMETRIC'] +
        0.10 * features['INCOMPLETE_NO_DATA']
    )
    
    return features


def calculate_efficiency_features(features: pd.DataFrame) -> pd.DataFrame:
    """Calculate connection efficiency features"""
    
    # Payload efficiency (assuming ~40 bytes header per packet)
    header_overhead = features['PACKETS_TOTAL'] * 40
    features['PAYLOAD_RATIO'] = np.where(
        features['BYTES_TOTAL'] > 0,
        (features['BYTES_TOTAL'] - header_overhead) / features['BYTES_TOTAL'],
        0
    )
    features['PAYLOAD_RATIO'] = features['PAYLOAD_RATIO'].clip(0, 1)
    
    # Data exchange efficiency (bytes received per byte sent)
    features['EXCHANGE_EFFICIENCY'] = np.where(
        features['BYTES'] > 0,
        features['BYTES_REV'] / features['BYTES'],
        0
    )
    
    return features


def add_label(features: pd.DataFrame, label: str) -> pd.DataFrame:
    """Add label column"""
    features['LABEL'] = label
    return features


def extract_all_features(
    input_file: str,
    output_file: str,
    label: str = "Benign"
):
    """Extract all features from Zeek conn.log"""
    
    # Parse Zeek log
    df = parse_zeek_conn_log(input_file)
    
    print("Calculating features...")
    
    # Extract features
    features = calculate_basic_features(df)
    features = calculate_rate_features(features)
    features = calculate_ratio_features(features)
    features = calculate_packet_size_features(features)
    features = calculate_timing_features(features)
    features = calculate_bidirectional_features(features)
    features = calculate_state_features(df, features)
    features = calculate_dos_signature_features(features)
    features = calculate_efficiency_features(features)
    features = add_label(features, label)
    
    print(f"Calculated {len(features.columns)} features")
    
    # Replace inf/-inf with 0
    features = features.replace([np.inf, -np.inf], 0)
    
    # Fill NaN with 0
    features = features.fillna(0)
    
    # Save
    features.to_csv(output_file, index=False)
    print(f"\n✓ Features saved to: {output_file}")
    
    # Display statistics
    print("\n" + "="*60)
    print(f"FEATURE EXTRACTION SUMMARY - {label}")
    print("="*60)
    print(f"\nTotal flows: {len(features)}")
    print(f"Total features: {len(features.columns) - 1}")  # Exclude LABEL
    
    print("\n--- Key Statistics ---")
    key_features = ['PACKETS', 'PACKETS_REV', 'DURATION', 'PPI', 
                   'ROUNDTRIPS', 'DOS_SCORE', 'FLOW_ENDREASON_IDLE']
    
    for feat in key_features:
        if feat in features.columns:
            print(f"{feat:25s}: mean={features[feat].mean():.2f}, "
                  f"std={features[feat].std():.2f}")
    
    print("\n--- DoS Signature Distribution ---")
    dos_features = ['SHORT_LIVED', 'NO_RESPONSE', 'HIGH_RATE', 
                   'IS_INCOMPLETE', 'HIGHLY_ASYMMETRIC']
    
    for feat in dos_features:
        if feat in features.columns:
            count = features[feat].sum()
            pct = (count / len(features)) * 100
            print(f"{feat:25s}: {count:6d} ({pct:5.1f}%)")
    
    print("\n--- Flow End Reason Distribution ---")
    idle_pct = features['FLOW_ENDREASON_IDLE'].mean() * 100
    active_pct = features['FLOW_ENDREASON_ACTIVE'].mean() * 100
    other_pct = features['FLOW_ENDREASON_OTHER'].mean() * 100
    
    print(f"IDLE:   {idle_pct:5.1f}%")
    print(f"ACTIVE: {active_pct:5.1f}%")
    print(f"OTHER:  {other_pct:5.1f}%")
    
    return features


def main():
    parser = argparse.ArgumentParser(
        description="Advanced QUIC Flow Feature Extraction"
    )
    parser.add_argument(
        '--input',
        required=True,
        help='Input Zeek conn.log file'
    )
    parser.add_argument(
        '--output',
        required=True,
        help='Output CSV file'
    )
    parser.add_argument(
        '--label',
        default='Benign',
        choices=['Benign', 'Malicious'],
        help='Traffic label'
    )
    
    args = parser.parse_args()
    
    # Validate input file
    if not Path(args.input).exists():
        print(f"Error: Input file not found: {args.input}")
        return
    
    # Extract features
    extract_all_features(
        input_file=args.input,
        output_file=args.output,
        label=args.label
    )


if __name__ == "__main__":
    main()