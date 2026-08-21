"""Small in-process WebSocket fan-out for the modular-monolith prototype."""
import asyncio
from collections import defaultdict
from typing import Any

from fastapi import WebSocket


class LiveHub:
    def __init__(self) -> None:
        self._connections: dict[str, set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def connect(self, topic: str, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections[topic].add(websocket)

    async def disconnect(self, topic: str, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections[topic].discard(websocket)

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        async with self._lock:
            connections = list(self._connections[topic])
        stale: list[WebSocket] = []
        for websocket in connections:
            try:
                await websocket.send_json(payload)
            except RuntimeError:
                stale.append(websocket)
        for websocket in stale:
            await self.disconnect(topic, websocket)


hub = LiveHub()
