#!/usr/bin/env python3
"""
Comprehensive Statistical Analysis of Zeek conn.log Files
Compares:
 - Benign vs Malicious (overall)
 - Benign SF vs Malicious SF
 - Malicious S0 vs Benign SF

Includes:
 - Descriptive statistics
 - Effect size (Cohen's d)
 - Welch t-test (unequal variance)
"""

import pandas as pd
import numpy as np
import argparse
from scipy import stats


# ===============================
# Parsing Zeek conn.log
# ===============================

def parse_conn_log(filepath):
    columns = [
        'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
        'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
        'conn_state', 'local_orig', 'local_resp', 'missed_bytes',
        'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts',
        'resp_ip_bytes', 'tunnel_parents', 'ip_proto'
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

    return df


# ===============================
# Feature Engineering (minimal)
# ===============================

def add_basic_features(df):
    df = df.copy()
    df['PACKETS_TOTAL'] = df['orig_pkts'] + df['resp_pkts']
    df['BYTES_TOTAL'] = df['orig_bytes'] + df['resp_bytes']
    df['ROUNDTRIPS'] = np.minimum(df['orig_pkts'], df['resp_pkts'])
    df['ASYMMETRY'] = np.where(
        df['PACKETS_TOTAL'] > 0,
        abs(df['orig_pkts'] - df['resp_pkts']) / df['PACKETS_TOTAL'],
        0
    )
    df['PPI'] = np.where(df['duration'] > 0,
                         df['orig_pkts'] / df['duration'],
                         0)
    return df


# ===============================
# Statistical Comparison
# ===============================

def cohen_d(x, y):
    nx = len(x)
    ny = len(y)
    pooled_std = np.sqrt(
        ((nx - 1) * np.var(x) + (ny - 1) * np.var(y)) / (nx + ny - 2)
    )
    if pooled_std == 0:
        return 0
    return (np.mean(x) - np.mean(y)) / pooled_std


def compare_groups(df1, df2, label1, label2):
    features = [
        'duration',
        'orig_pkts',
        'resp_pkts',
        'PACKETS_TOTAL',
        'BYTES_TOTAL',
        'ROUNDTRIPS',
        'ASYMMETRY',
        'PPI'
    ]

    print("\n" + "="*80)
    print(f"COMPARISON: {label1} vs {label2}")
    print("="*80)

    for feature in features:
        x = df1[feature]
        y = df2[feature]

        t_stat, p_value = stats.ttest_ind(x, y, equal_var=False)

        d = cohen_d(x, y)

        print(f"\nFeature: {feature}")
        print(f"{label1} mean: {np.mean(x):.4f}")
        print(f"{label2} mean: {np.mean(y):.4f}")
        print(f"p-value (Welch t-test): {p_value:.4e}")
        print(f"Cohen's d: {d:.4f}")

        if abs(d) > 0.8:
            print("Effect size: LARGE")
        elif abs(d) > 0.5:
            print("Effect size: MEDIUM")
        elif abs(d) > 0.2:
            print("Effect size: SMALL")
        else:
            print("Effect size: NEGLIGIBLE")


# ===============================
# Main
# ===============================

def main():
    parser = argparse.ArgumentParser(
        description="Statistical comparison of Zeek conn.log datasets"
    )
    parser.add_argument('--benign', required=True,
                        help='Benign conn.log file')
    parser.add_argument('--malicious', required=True,
                        help='Malicious conn.log file')

    args = parser.parse_args()

    print("\nLoading datasets...")
    benign = parse_conn_log(args.benign)
    malicious = parse_conn_log(args.malicious)

    benign = add_basic_features(benign)
    malicious = add_basic_features(malicious)

    print("\nDataset sizes:")
    print(f"Benign: {len(benign)}")
    print(f"Malicious: {len(malicious)}")

    # Overall comparison
    compare_groups(benign, malicious,
                   "Benign (All)", "Malicious (All)")

    # SF comparison
    benign_sf = benign[benign['conn_state'] == 'SF']
    malicious_sf = malicious[malicious['conn_state'] == 'SF']

    compare_groups(benign_sf, malicious_sf,
                   "Benign SF", "Malicious SF")

    # S0 vs Benign SF
    malicious_s0 = malicious[malicious['conn_state'] == 'S0']

    compare_groups(benign_sf, malicious_s0,
                   "Benign SF", "Malicious S0")


if __name__ == "__main__":
    main()
