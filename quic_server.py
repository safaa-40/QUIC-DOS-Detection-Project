#!/usr/bin/env python3
"""
Simple QUIC/HTTP3 Server for Research Traffic Capture
Based on aioquic examples with minimal dependencies
"""

import asyncio
import argparse
import logging
from typing import Dict, Optional
from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived, H3Event
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("quic_server")


class HttpServerProtocol(QuicConnectionProtocol):
    """Simple HTTP/3 server protocol"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
    
    def quic_event_received(self, event: QuicEvent):
        """Handle QUIC events"""
        # Process HTTP/3 events
        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                self.http_event_received(http_event)
    
    def http_event_received(self, event: HeadersReceived):
        """Handle HTTP/3 requests"""
        headers = dict(event.headers)
        method = headers.get(b":method", b"GET")
        path = headers.get(b":path", b"/")
        
        logger.debug(f"Request: {method.decode()} {path.decode()}")
        
        # Prepare response
        response_headers = [
            (b":status", b"200"),
            (b"server", b"aioquic-research/1.0"),
            (b"content-type", b"text/plain"),
        ]
        
        response_body = b"OK - QUIC Server for Research"
        
        # Send response
        self._http.send_headers(
            stream_id=event.stream_id,
            headers=response_headers,
            end_stream=False
        )
        
        self._http.send_data(
            stream_id=event.stream_id,
            data=response_body,
            end_stream=True
        )
        
        # Transmit
        self.transmit()


async def main():
    parser = argparse.ArgumentParser(description="QUIC/HTTP3 Server for Research")
    parser.add_argument("--host", default="::", help="Host to bind")
    parser.add_argument("--port", type=int, default=4433, help="Port to bind")
    parser.add_argument("--certificate", required=True, help="TLS certificate file")
    parser.add_argument("--private-key", required=True, help="TLS private key file")
    
    args = parser.parse_args()
    
    # Configuration
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=H3_ALPN,
    )
    
    # Load certificate and key
    configuration.load_cert_chain(args.certificate, args.private_key)
    
    logger.info(f"Starting QUIC server on {args.host}:{args.port}")
    
    # Start server
    await serve(
        host=args.host,
        port=args.port,
        configuration=configuration,
        create_protocol=HttpServerProtocol,
    )
    
    # Run forever
    await asyncio.Future()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped")
