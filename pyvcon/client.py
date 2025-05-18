import asyncio
import struct

class PavlovRCON:
    def __init__(self, host: str, port: int, password: str):
        self.host = host
        self.port = port
        self.password = password
        self.reader = None
        self.writer = None

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        await self._authenticate()

    async def _authenticate(self):
        await self._send_packet(0, 3, self.password)
        packet_id, packet_type, _ = await self._receive_packet()
        if packet_type == -1:
            raise Exception("RCON authentication failed")

    async def send(self, command: str) -> str:
        await self._send_packet(1, 2, command)
        _, _, response = await self._receive_packet()
        return response.decode('utf-8', errors='ignore')

    async def close(self):
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()

    async def _send_packet(self, packet_id, packet_type, body):
        data = struct.pack('<iii', packet_id, packet_type, len(body) + 2) + body.encode('utf-8') + b'\x00\x00'
        self.writer.write(data)
        await self.writer.drain()

    async def _receive_packet(self):
        header = await self.reader.readexactly(12)
        packet_id, packet_type, body_len = struct.unpack('<iii', header)
        body = await self.reader.readexactly(body_len)
        return packet_id, packet_type, body
