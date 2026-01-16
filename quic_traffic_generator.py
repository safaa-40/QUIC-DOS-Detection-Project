#!/usr/bin/env python3
"""
QUIC Traffic Generator for DoS Simulation Research
Generates both benign and malicious QUIC traffic using aioquic
Based on verified aioquic documentation and examples
"""

import asyncio
import random
import argparse
import logging
from typing import Optional
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("quic_traffic_gen")


class HttpClientProtocol(QuicConnectionProtocol):
    """Custom protocol for HTTP/3 client"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._request_events = {}
        self._request_waiter = {}
    
    async def make_request(self, path: str = "/"):
        """Make a simple HTTP/3 GET request"""
        stream_id = self._quic.get_next_available_stream_id()
        
        # Prepare HTTP/3 headers
        headers = [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"localhost"),
            (b":path", path.encode()),
            (b"user-agent", b"quic-research-client/1.0"),
        ]
        
        # Send request
        self._http.send_headers(stream_id=stream_id, headers=headers, end_stream=True)
        
        # Create waiter for response
        waiter = self._loop.create_future()
        self._request_events[stream_id] = []
        self._request_waiter[stream_id] = waiter
        
        # Transmit
        self.transmit()
        
        # Wait for response
        try:
            await asyncio.wait_for(waiter, timeout=5.0)
        except asyncio.TimeoutError:
            logger.debug(f"Request on stream {stream_id} timed out")
    
    def quic_event_received(self, event: QuicEvent):
        """Handle QUIC events"""
        # Process HTTP/3 events
        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                stream_id = http_event.stream_id
                if stream_id in self._request_events:
                    self._request_events[stream_id].append(http_event)
                    
            elif isinstance(http_event, DataReceived):
                stream_id = http_event.stream_id
                if stream_id in self._request_events:
                    self._request_events[stream_id].append(http_event)
                    
                    # If stream ended, complete the request
                    if http_event.stream_ended:
                        if stream_id in self._request_waiter:
                            waiter = self._request_waiter.pop(stream_id)
                            if not waiter.done():
                                waiter.set_result(None)


# ============================================================================
# BENIGN TRAFFIC GENERATION
# ============================================================================

async def benign_quic_session(server_ip: str, server_port: int, session_duration: float):
    """
    Generate realistic benign QUIC traffic:
    - Complete handshake
    - Exchange HTTP/3 data
    - Natural session duration
    """
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        verify_mode=False  # For self-signed certs
    )
    
    try:
        async with connect(
            server_ip,
            server_port,
            configuration=configuration,
            create_protocol=HttpClientProtocol,
            wait_connected=True  # Wait for handshake completion
        ) as client:
            client = client  # Type hint
            
            # Make 1-5 requests during the session
            num_requests = random.randint(1, 5)
            for i in range(num_requests):
                paths = ["/", "/index.html", "/api/data", "/health", "/status"]
                path = random.choice(paths)
                
                try:
                    await client.make_request(path)
                    logger.debug(f"Benign request {i+1}/{num_requests} to {path}")
                except Exception as e:
                    logger.debug(f"Request failed: {e}")
                
                # Inter-request delay
                await asyncio.sleep(random.uniform(0.1, 1.0))
            
            # Keep connection alive for session duration
            remaining_time = session_duration - random.uniform(0.5, 2.0)
            if remaining_time > 0:
                await asyncio.sleep(remaining_time)
                
    except Exception as e:
        logger.debug(f"Benign session error: {e}")


async def generate_benign_traffic(
    server_ip: str,
    server_port: int,
    num_sessions: int,
    duration_seconds: int
):
    """Generate benign QUIC traffic over specified duration"""
    logger.info(f"Starting benign traffic generation: {num_sessions} sessions over {duration_seconds}s")
    
    start_time = asyncio.get_event_loop().time()
    end_time = start_time + duration_seconds
    sessions_launched = 0
    
    while asyncio.get_event_loop().time() < end_time and sessions_launched < num_sessions:
        # Session duration: 1-10 seconds
        session_duration = random.uniform(1.0, 10.0)
        
        # Launch session
        asyncio.create_task(benign_quic_session(server_ip, server_port, session_duration))
        sessions_launched += 1
        
        if sessions_launched % 100 == 0:
            logger.info(f"Benign traffic: {sessions_launched}/{num_sessions} sessions launched")
        
        # Inter-session delay (Poisson-like distribution)
        # Average ~2 new sessions per second
        delay = random.expovariate(2.0)
        await asyncio.sleep(delay)
    
    logger.info(f"Benign traffic generation complete: {sessions_launched} sessions")
    
    # Wait for all sessions to complete
    await asyncio.sleep(15)


# ============================================================================
# MAIN CLI
# ============================================================================

async def main():
    parser = argparse.ArgumentParser(description="QUIC Traffic Generator for Research")
    parser.add_argument("--server", required=True, help="Server IP address")
    parser.add_argument("--port", type=int, default=4433, help="Server port")
    parser.add_argument("--mode", choices=["benign"], required=True)
    parser.add_argument("--duration", type=int, default=1800, help="Duration in seconds")
    
    # Benign-specific
    parser.add_argument("--sessions", type=int, default=1000, help="Number of sessions (benign mode)")
    
    args = parser.parse_args()
    
    if args.mode == "benign":
        await generate_benign_traffic(
            server_ip=args.server,
            server_port=args.port,
            num_sessions=args.sessions,
            duration_seconds=args.duration
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Traffic generation interrupted by user")
