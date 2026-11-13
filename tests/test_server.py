import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from server import Relay  # noqa: E402


async def start(**kw):
    relay = Relay(**kw)
    srv = await relay.start('127.0.0.1', 0)
    port = srv.sockets[0].getsockname()[1]
    return relay, srv, port


async def connect(port):
    return await asyncio.open_connection('127.0.0.1', port)


async def settle():
    await asyncio.sleep(0.05)


async def readline(r, t=2):
    return await asyncio.wait_for(r.readline(), t)


@pytest.mark.asyncio
async def test_broadcast_excludes_sender():
    relay, srv, port = await start()
    (r1, w1), (r2, w2), (r3, w3) = [await connect(port) for _ in range(3)]
    await settle()
    w1.write(b'hello\n')
    await w1.drain()
    assert await readline(r2) == b'hello\n'
    assert await readline(r3) == b'hello\n'
    with pytest.raises(asyncio.TimeoutError):
        await readline(r1, 0.3)
    srv.close()


@pytest.mark.asyncio
async def test_oversized_packet_disconnects_sender_only():
    relay, srv, port = await start(max_payload=1024)
    (r1, w1), (r2, w2) = await connect(port), await connect(port)
    await settle()
    w1.write(b'x' * 5000 + b'\n')
    await w1.drain()
    assert await asyncio.wait_for(r1.read(), 2) == b''      # sender was cut off
    w2.write(b'still alive\n')
    await w2.drain()
    await settle()
    assert len(relay.clients) == 1
    srv.close()


@pytest.mark.asyncio
async def test_packet_exactly_at_limit_is_relayed():
    relay, srv, port = await start(max_payload=1024)
    (r1, w1), (r2, w2) = await connect(port), await connect(port)
    await settle()
    w1.write(b'y' * 1023 + b'\n')
    await w1.drain()
    assert len(await readline(r2)) == 1024
    srv.close()


@pytest.mark.asyncio
async def test_rate_limit_drops_but_keeps_connection():
    relay, srv, port = await start(rate_msgs=3, rate_window=10, rate_strikes=1000)
    (r1, w1), (r2, w2) = await connect(port), await connect(port)
    await settle()
    for i in range(10):
        w1.write(b'm%d\n' % i)
    await w1.drain()
    got = []
    try:
        while True:
            got.append(await readline(r2, 0.4))
    except asyncio.TimeoutError:
        pass
    assert got == [b'm0\n', b'm1\n', b'm2\n']
    assert len(relay.clients) == 2
    srv.close()


@pytest.mark.asyncio
async def test_flooding_gets_disconnected():
    relay, srv, port = await start(rate_msgs=1, rate_window=10, rate_strikes=5)
    r1, w1 = await connect(port)
    await settle()
    for _ in range(20):
        w1.write(b'spam\n')
    await w1.drain()
    assert await asyncio.wait_for(r1.read(), 2) == b''
    srv.close()


@pytest.mark.asyncio
async def test_per_ip_limit():
    relay, srv, port = await start(max_per_ip=2)
    conns = [await connect(port) for _ in range(3)]
    await settle()
    assert len(relay.clients) == 2
    assert await asyncio.wait_for(conns[2][0].read(), 2) == b''   # third was rejected
    # freeing a slot lets a new one in
    conns[0][1].close()
    await settle()
    r, w = await connect(port)
    await settle()
    assert len(relay.clients) == 2
    srv.close()


@pytest.mark.asyncio
async def test_total_limit():
    relay, srv, port = await start(max_connections=2, max_per_ip=10)
    conns = [await connect(port) for _ in range(3)]
    await settle()
    assert len(relay.clients) == 2
    srv.close()


@pytest.mark.asyncio
async def test_slow_reader_does_not_block_others_and_is_dropped():
    relay, srv, port = await start(queue_max=8, write_timeout=1, max_payload=65536, rate_msgs=100000)
    (rs, ws) = await connect(port)           # sender
    (rf, wf) = await connect(port)           # fast reader
    (rl, wl) = await connect(port)           # never reads
    await settle()
    chunk = b'z' * 60000 + b'\n'
    count = 0

    async def drain_fast():
        nonlocal count
        while True:
            line = await rf.readline()
            if not line:
                return
            count += 1
    task = asyncio.create_task(drain_fast())
    for _ in range(200):
        ws.write(chunk)
        await ws.drain()
    await asyncio.sleep(0.5)
    assert count == 200                      # fast reader got everything despite the stalled one
    await asyncio.sleep(1.5)
    assert len(relay.clients) == 2           # stalled client evicted (sender + fast reader remain)
    task.cancel()
    srv.close()


@pytest.mark.asyncio
async def test_partial_line_times_out():
    relay, srv, port = await start(line_timeout=0.3)
    r, w = await connect(port)
    await settle()
    w.write(b'no newline')
    await w.drain()
    assert await asyncio.wait_for(r.read(), 2) == b''
    srv.close()


@pytest.mark.asyncio
async def test_idle_timeout():
    relay, srv, port = await start(idle_timeout=0.3)
    r, w = await connect(port)
    assert await asyncio.wait_for(r.read(), 2) == b''
    srv.close()


@pytest.mark.asyncio
async def test_empty_lines_are_ignored_not_relayed():
    relay, srv, port = await start()
    (r1, w1), (r2, w2) = await connect(port), await connect(port)
    await settle()
    w1.write(b'\n\n\nreal\n')
    await w1.drain()
    assert await readline(r2) == b'real\n'
    srv.close()
