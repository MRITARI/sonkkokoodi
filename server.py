import asyncio
import logging
import time
from collections import defaultdict

# --- INFRASTRUCTURE LIMITS ---
HOST = '0.0.0.0'
PORT = 9999
MAX_CONNECTIONS = 50          # Prevent connection exhaustion
MAX_PAYLOAD_SIZE = 8192       # 8 KB max per message (prevents memory DoS)
RATE_LIMIT_MSGS = 10          # Max messages...
RATE_LIMIT_WINDOW = 1.0       # ...per this many seconds
IDLE_TIMEOUT = 3600           # Disconnect silent sockets after 1 hour

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Global State
active_clients = set()

async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    ip = addr[0]

    if len(active_clients) >= MAX_CONNECTIONS:
        logging.warning(f"[!] Connection rejected from {ip}: Server full.")
        writer.close()
        await writer.wait_closed()
        return

    active_clients.add(writer)
    logging.info(f"[+] Connected: {ip}. Total active: {len(active_clients)}")

    message_timestamps = []

    try:
        while True:
            try:
                # readuntil() protects against memory exhaustion by strictly enforcing the limit parameter set in start_server
                data = await asyncio.wait_for(
                    reader.readuntil(separator=b'\n'), 
                    timeout=IDLE_TIMEOUT
                )
            except asyncio.exceptions.LimitOverrunError:
                logging.warning(f"[!] {ip} exceeded {MAX_PAYLOAD_SIZE} bytes. Severing connection.")
                break
            except asyncio.IncompleteReadError:
                # Normal disconnect
                break
            except asyncio.TimeoutError:
                logging.info(f"[-] {ip} timed out due to inactivity.")
                break

            if not data:
                break

            # --- RATE LIMITING ---
            now = time.time()
            message_timestamps = [t for t in message_timestamps if now - t < RATE_LIMIT_WINDOW]
            if len(message_timestamps) >= RATE_LIMIT_MSGS:
                logging.warning(f"[!] {ip} rate limited. Packet dropped.")
                continue # Drop the packet, don't disconnect
            
            message_timestamps.append(now)

            # --- BROADCAST ---
            await broadcast(data, exclude_writer=writer)

    except ConnectionResetError:
        pass # Client forcibly closed the connection
    except Exception as e:
        logging.error(f"[!] Unexpected error with {ip}: {e}")
    finally:
        active_clients.discard(writer)
        logging.info(f"[-] Disconnected: {ip}. Total active: {len(active_clients)}")
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

async def broadcast(data: bytes, exclude_writer: asyncio.StreamWriter):
    """Safely iterates through active clients and sends data."""
    dead_clients = set()
    
    for client in active_clients:
        if client != exclude_writer:
            try:
                client.write(data)
                await client.drain()
            except Exception:
                # If a socket is broken but hasn't fully closed yet, mark it for execution
                dead_clients.add(client)

    # Clean up ghost sockets
    for dead in dead_clients:
        active_clients.discard(dead)
        dead.close()

async def main():
    # The 'limit' parameter is critical: it enforces the maximum bytes reader.readuntil() will buffer
    server = await asyncio.start_server(
        handle_client, 
        HOST, 
        PORT, 
        limit=MAX_PAYLOAD_SIZE 
    )
    
    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    logging.info(f"[*] Sönkkökoodi Secure Relay active on {addrs}")
    logging.info(f"[*] Max connections: {MAX_CONNECTIONS} | Max payload: {MAX_PAYLOAD_SIZE} bytes")

    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("\n[*] Server shutting down via keyboard interrupt.")
