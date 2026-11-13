"""Sönkkökoodi blind relay.

Newline-delimited packets from any client are forwarded verbatim to every other client.
The relay never parses, stores or decrypts anything. It DOES see metadata: client IPs,
connection times, packet sizes and timing.

Optional TLS:  python server.py --cert fullchain.pem --key privkey.pem
(Clients currently speak plain TCP, so TLS is only useful behind a TLS-terminating proxy
or once the client gains TLS support.)
"""
import argparse
import asyncio
import logging
import ssl
import time
from collections import defaultdict

# --- INFRASTRUCTURE LIMITS (overridable per Relay instance) ---
HOST = '0.0.0.0'
PORT = 9999
MAX_CONNECTIONS = 50          # total sockets
MAX_CONNECTIONS_PER_IP = 5    # one address cannot occupy every slot
MAX_PAYLOAD_SIZE = 8192       # bytes per packet (including the newline)
RATE_LIMIT_MSGS = 10          # packets...
RATE_LIMIT_WINDOW = 1.0       # ...per this many seconds
RATE_LIMIT_STRIKES = 50       # consecutive dropped packets before the client is disconnected
IDLE_TIMEOUT = 3600           # silent sockets are dropped after this many seconds
LINE_TIMEOUT = 30             # a packet that has started must be completed within this time
SEND_QUEUE_MAX = 64           # packets queued per client; a client that falls this far behind is dropped
WRITE_TIMEOUT = 5             # a single drain() may not stall longer than this


class Client:
    """One connection: a reader loop (handle) and a dedicated writer task fed by a bounded queue."""

    def __init__(self, reader, writer, ip):
        self.reader = reader
        self.writer = writer
        self.ip = ip
        self.queue = asyncio.Queue(maxsize=SEND_QUEUE_MAX)
        self.writer_task = None
        self.dead = False

    def kill(self):
        """Drop immediately. close() would wait to flush data a stalled peer never reads."""
        self.dead = True
        try:
            self.writer.transport.abort()
        except Exception:
            self.writer.close()


class Relay:
    def __init__(self, max_connections=MAX_CONNECTIONS, max_per_ip=MAX_CONNECTIONS_PER_IP,
                 max_payload=MAX_PAYLOAD_SIZE, rate_msgs=RATE_LIMIT_MSGS, rate_window=RATE_LIMIT_WINDOW,
                 rate_strikes=RATE_LIMIT_STRIKES, idle_timeout=IDLE_TIMEOUT, line_timeout=LINE_TIMEOUT,
                 queue_max=SEND_QUEUE_MAX, write_timeout=WRITE_TIMEOUT):
        self.max_connections = max_connections
        self.max_per_ip = max_per_ip
        self.max_payload = max_payload
        self.rate_msgs = rate_msgs
        self.rate_window = rate_window
        self.rate_strikes = rate_strikes
        self.idle_timeout = idle_timeout
        self.line_timeout = line_timeout
        self.queue_max = queue_max
        self.write_timeout = write_timeout
        self.clients = set()
        self.per_ip = defaultdict(int)

    # ---- per-client writer -------------------------------------------------------------
    async def _writer_loop(self, c):
        try:
            while True:
                data = await c.queue.get()
                c.writer.write(data)
                await asyncio.wait_for(c.writer.drain(), timeout=self.write_timeout)
        except asyncio.CancelledError:
            raise
        except Exception:
            # Broken or stalled socket: aborting it makes the reader loop exit.
            c.kill()

    def broadcast(self, data, sender):
        """Never blocks: a slow receiver only ever hurts itself."""
        for c in list(self.clients):
            if c is sender or c.dead:
                continue
            try:
                c.queue.put_nowait(data)
            except asyncio.QueueFull:
                logging.warning("[!] %s fell too far behind. Dropping client.", c.ip)
                c.kill()

    # ---- connection handling -----------------------------------------------------------
    async def handle(self, reader, writer):
        peer = writer.get_extra_info('peername')
        ip = peer[0] if peer else 'unknown'

        if len(self.clients) >= self.max_connections or self.per_ip[ip] >= self.max_per_ip:
            logging.warning("[!] Connection rejected from %s (limit reached).", ip)
            writer.close()
            return

        c = Client(reader, writer, ip)
        c.queue = asyncio.Queue(maxsize=self.queue_max)
        self.clients.add(c)
        self.per_ip[ip] += 1
        c.writer_task = asyncio.create_task(self._writer_loop(c))
        logging.info("[+] Connected: %s. Total active: %d", ip, len(self.clients))

        stamps = []
        strikes = 0
        try:
            while True:
                try:
                    # Wait (up to idle_timeout) for the first byte of a packet, then require the rest promptly.
                    first = await asyncio.wait_for(reader.read(1), timeout=self.idle_timeout)
                    if not first:
                        break
                    if first == b'\n':
                        continue
                    rest = await asyncio.wait_for(reader.readuntil(b'\n'), timeout=self.line_timeout)
                    data = first + rest
                except asyncio.LimitOverrunError:
                    logging.warning("[!] %s exceeded the packet size limit. Severing connection.", ip)
                    break
                except asyncio.IncompleteReadError:
                    break
                except asyncio.TimeoutError:
                    logging.info("[-] %s timed out.", ip)
                    break

                if len(data) > self.max_payload:
                    logging.warning("[!] %s sent an oversized packet. Severing connection.", ip)
                    break

                now = time.monotonic()
                stamps = [t for t in stamps if now - t < self.rate_window]
                if len(stamps) >= self.rate_msgs:
                    strikes += 1
                    if strikes >= self.rate_strikes:
                        logging.warning("[!] %s keeps flooding. Severing connection.", ip)
                        break
                    continue            # drop the packet, keep the connection
                strikes = 0
                stamps.append(now)

                self.broadcast(data, c)
        except (ConnectionError, OSError):
            pass
        except Exception as e:
            logging.error("[!] Unexpected error with %s: %s", ip, type(e).__name__)
        finally:
            self.clients.discard(c)
            self.per_ip[ip] -= 1
            if self.per_ip[ip] <= 0:
                del self.per_ip[ip]
            c.writer_task.cancel()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logging.info("[-] Disconnected: %s. Total active: %d", ip, len(self.clients))

    async def start(self, host=HOST, port=PORT, ssl_ctx=None):
        # `limit` is the StreamReader buffer: a packet can never grow beyond it.
        return await asyncio.start_server(self.handle, host, port, limit=self.max_payload, ssl=ssl_ctx)


async def main(args):
    ctx = None
    if args.cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(args.cert, args.key)
    relay = Relay()
    server = await relay.start(args.host, args.port, ctx)
    addrs = ', '.join(str(s.getsockname()) for s in server.sockets)
    logging.info("[*] Sönkkökoodi relay active on %s (TLS: %s)", addrs, 'yes' if ctx else 'no')
    logging.info("[*] Limits: %d conns (%d per IP), %d byte packets", relay.max_connections, relay.max_per_ip, relay.max_payload)
    logging.info("[*] Note: the relay sees IPs, timing and packet sizes (never plaintext).")
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default=HOST)
    ap.add_argument('--port', type=int, default=PORT)
    ap.add_argument('--cert')
    ap.add_argument('--key')
    a = ap.parse_args()
    try:
        asyncio.run(main(a))
    except KeyboardInterrupt:
        logging.info("[*] Shutting down.")
