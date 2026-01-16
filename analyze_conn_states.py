#!/usr/bin/env python3
"""
Analyze Zeek conn_state values in your logs
This will show us what states are actually present
"""

import sys
from collections import Counter

def analyze_conn_states(log_file):
    """Parse conn.log and count conn_state values"""
    
    print(f"\nAnalyzing: {log_file}")
    print("="*70)
    
    states = []
    
    with open(log_file, 'r') as f:
        for line in f:
            # Skip comments
            if line.startswith('#'):
                continue
            
            fields = line.strip().split('\t')
            if len(fields) >= 12:
                conn_state = fields[11]
                if conn_state != '-':
                    states.append(conn_state)
    
    # Count states
    state_counts = Counter(states)
    total = len(states)
    
    print(f"\nTotal flows: {total}")
    print(f"\nConnection State Distribution:")
    print("-"*70)
    
    for state, count in state_counts.most_common():
        percentage = (count / total) * 100
        print(f"  {state:10s}: {count:6d} ({percentage:5.1f}%)")
    
    print("\n" + "="*70)
    print("Zeek Connection State Reference:")
    print("-"*70)
    print("  S0     : Connection attempt seen, no reply")
    print("  S1     : Connection established, not terminated")
    print("  SF     : Normal establishment and termination")
    print("  REJ    : Connection attempt rejected")
    print("  S2/S3  : Partial establishment")
    print("  RSTO   : Connection reset by originator")
    print("  RSTOS0 : Originator sent SYN, responder sent RST")
    print("  SH     : Originator sent data + FIN, no reply")
    print("="*70)
    
    return state_counts

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_conn_states.py <conn.log>")
        sys.exit(1)
    
    for log_file in sys.argv[1:]:
        try:
            analyze_conn_states(log_file)
        except FileNotFoundError:
            print(f"Error: File not found: {log_file}")
        except Exception as e:
            print(f"Error analyzing {log_file}: {e}")