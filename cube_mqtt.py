#!/usr/bin/env python3
import asyncio
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from bleak import BleakClient, BleakScanner
import paho.mqtt.client as mqtt

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

# We no longer trust the cube's MAC address because it may change.
# Instead we discover it by looking for a stable BLE advertisement service-data key.
TARGET_SERVICE_DATA_UUID = "0000fe95-0000-1000-8000-00805f9b34fb"

# These are the GATT UUIDs used after we connect to the cube.
SERVICE_UUID = "0000aadb-0000-1000-8000-00805f9b34fb"
CHAR_UUID = "0000aadc-0000-1000-8000-00805f9b34fb"

# MQTT topics are published under this base path.
MQTT_BASE = "cube/smart"
MQTT_CLIENT_ID = "cube-pi4"

# Default MQTT settings. These are overridden by .env if present.
MQTT_HOST_DEFAULT = "192.168.2.110"
MQTT_PORT_DEFAULT = 1883

# Home Assistant MQTT Discovery prefix
HA_DISCOVERY_PREFIX = "homeassistant"

# If your broker requires login, put those values in .env.
# Example:
# MQTT_HOST=192.168.2.110
# MQTT_PORT=1883
# MQTT_USER=myuser
# MQTT_PASS=mypassword

# Decryption key used by newer encrypted cube packets.
DECRYPTION_KEY = bytes([
    176, 81, 104, 224, 86, 137, 237, 119, 38, 26, 193, 161, 210, 126, 150, 81,
    93, 13, 236, 249, 89, 235, 88, 24, 113, 81, 214, 131, 130, 199, 2, 169, 39, 165, 171, 41
])

# This is the byte pattern for a solved cube as used by the original sketch.
SOLUTION = bytes([0x12, 0x34, 0x56, 0x78, 0x33, 0x33, 0x33, 0x33,
                  0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0x00, 0x00])

# Human-readable names for the face index stored in the packet.
FACE_NAMES = ["Front", "Bottom", "Right", "Top", "Left", "Back"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger("cube")

# -----------------------------------------------------------------------------
# Data structures
# -----------------------------------------------------------------------------

@dataclass
class Config:
    mqtt_host: str = MQTT_HOST_DEFAULT
    mqtt_port: int = MQTT_PORT_DEFAULT
    mqtt_user: str = ""
    mqtt_pass: str = ""

@dataclass
class CubeState:
    raw: bytes
    decoded: bytes
    encrypted: bool
    solved: bool
    last_face: Optional[str]
    last_direction: Optional[str]

# -----------------------------------------------------------------------------
# Helper functions
# -----------------------------------------------------------------------------

def load_env_file(path: str = ".env") -> Config:
    """Read simple KEY=VALUE settings from a local .env file.

    This is intentionally very small and dependency-free.
    The file is optional, but if present it can override MQTT settings.
    """
    cfg = Config()
    p = Path(path)
    if not p.exists():
        return cfg

    try:
        text = p.read_text()
    except PermissionError as e:
        raise PermissionError(
            f"Cannot read {path}. Fix ownership/permissions, e.g. 'sudo chown pi:pi {path} && chmod 600 {path}'"
        ) from e

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")

        if key == "MQTT_HOST":
            cfg.mqtt_host = value
        elif key == "MQTT_PORT":
            try:
                cfg.mqtt_port = int(value)
            except ValueError:
                log.warning("Invalid MQTT_PORT in %s: %s", path, value)
        elif key == "MQTT_USER":
            cfg.mqtt_user = value
        elif key == "MQTT_PASS":
            cfg.mqtt_pass = value

    return cfg

def get_nibble(data: bytes, i: int) -> int:
    """Return nibble i from the byte array.

    i=0 means the high nibble of byte 0.
    i=1 means the low nibble of byte 0.
    i=2 means the high nibble of byte 1, etc.
    """
    b = data[i // 2]
    return b & 0x0F if i % 2 else (b >> 4) & 0x0F

def decode_packet(data: bytes) -> CubeState:
    """Decode a raw cube notification packet.

    The original cube sends a payload that may be either plain or encrypted.
    We detect encryption from byte 18 and, if needed, apply the same key logic
    used by the original ESP32 sketch.
    """
    if len(data) < 20:
        raise ValueError(f"Packet too short: {len(data)} bytes")

    buf = bytearray(data)
    encrypted = buf[18] == 0xA7

    if encrypted:
        offset1 = get_nibble(buf, 38)
        offset2 = get_nibble(buf, 39)

        # Guard against invalid offsets so malformed packets do not crash us.
        if offset1 + 19 >= len(DECRYPTION_KEY) or offset2 + 19 >= len(DECRYPTION_KEY):
            raise ValueError("Decryption offsets out of range")

        for i in range(20):
            buf[i] = (buf[i] + DECRYPTION_KEY[offset1 + i] + DECRYPTION_KEY[offset2 + i]) & 0xFF

    solved = bytes(buf[:16]) == SOLUTION

    # The packet stores the last move in two nibbles.
    # We validate the face index before using it.
    last_face = None
    last_direction = None
    face_idx = get_nibble(buf, 32)
    direction_idx = get_nibble(buf, 33)

    if 1 <= face_idx <= 6:
        last_face = FACE_NAMES[face_idx - 1]
        last_direction = "Clockwise" if direction_idx == 1 else "Anti-clockwise"

    return CubeState(
        raw=data,
        decoded=bytes(buf),
        encrypted=encrypted,
        solved=solved,
        last_face=last_face,
        last_direction=last_direction,
    )

async def discover_target_with_callback(timeout: float = 10.0):
    """Alternate scan method that inspects advertisement data in real time.

    This is the preferred discovery path when we need to filter by service data.
    """
    found = asyncio.Future()

    def detection_callback(device, advertisement_data):
        # Look for the FE95 service data key.
        if advertisement_data.service_data and TARGET_SERVICE_DATA_UUID in advertisement_data.service_data:
            if not found.done():
                found.set_result((device, advertisement_data))

    scanner = BleakScanner(detection_callback)
    await scanner.start()
    try:
        try:
            device, adv = await asyncio.wait_for(found, timeout=timeout)
            return device, adv
        except asyncio.TimeoutError:
            return None, None
    finally:
        await scanner.stop()

# -----------------------------------------------------------------------------
# MQTT bridge with Home Assistant Discovery
# -----------------------------------------------------------------------------

class MqttBridge:
    """Minimal MQTT publisher with async connect, reconnect, and HA discovery."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.connected = False
        self.client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=MQTT_CLIENT_ID,
            protocol=mqtt.MQTTv311,
        )
        # If a username is provided, enable authenticated login.
        if cfg.mqtt_user:
            self.client.username_pw_set(cfg.mqtt_user, cfg.mqtt_pass)

        self.client.on_connect = self.on_connect
        self.client.on_disconnect = self.on_disconnect
        # connect_async() avoids blocking startup if the broker is slow.
        self.client.connect_async(cfg.mqtt_host, cfg.mqtt_port, keepalive=60)
        self.client.loop_start()
        self.discovery_published = False

    def on_connect(self, client, userdata, flags, reason_code, properties=None):
        self.connected = True
        log.info("MQTT connected: %s", reason_code)
        client.publish(f"{MQTT_BASE}/connected", "1", retain=True)

    def on_disconnect(client, userdata, disconnect_flags, reason_code, properties):
        self.connected = False
        log.warning("MQTT disconnected: %s", reason_code)

    def publish(self, topic: str, payload: str, retain: bool = False):
        # Only publish when the client thinks it is connected.
        if self.connected:
            self.client.publish(topic, payload, retain=retain)

    def publish_discovery(self):
        """Publish Home Assistant MQTT discovery configs (retained)."""
        if self.discovery_published:
            return

        device_info = {
            "identifiers": ["smart_cube"],
            "name": "Smart Rubik's Cube",
            "model": "BLE Smart Cube",
            "manufacturer": "Mi",
            "via_device": MQTT_CLIENT_ID,
        }

        # Solved binary sensor
        solved_config = {
            "name": "Cube Solved",
            "unique_id": "smart_cube_solved",
            "state_topic": f"{MQTT_BASE}/solved",
            "device": device_info,
            "device_class": "problem",
            "payload_on": "1",
            "payload_off": "0",
            "icon": "mdi:dice-6"
        }
        topic = f"{HA_DISCOVERY_PREFIX}/binary_sensor/smart_cube_solved/config"
        self.publish(topic, json.dumps(solved_config), retain=True)

      # State sensor (decoded hex for cube layout)
        state_config = {
            "name": "Cube State",
            "unique_id": "smart_cube_state",
            "state_topic": f"{MQTT_BASE}/state",
            "device": device_info,
            "device_class": "enum",
            "icon": "mdi:cube"
        }
        topic = f"{HA_DISCOVERY_PREFIX}/sensor/smart_cube_state/config"
        self.publish(topic, json.dumps(state_config), retain=True)

        # Last Face sensor
        face_config = {
            "name": "Last Face",
            "unique_id": "smart_cube_last_face",
            "state_topic": f"{MQTT_BASE}/last_face",
            "device": device_info,
            "icon": "mdi:arrow-collapse-right"
        }
        topic = f"{HA_DISCOVERY_PREFIX}/sensor/smart_cube_last_face/config"
        self.publish(topic, json.dumps(face_config), retain=True)

        # Last Direction sensor
        direction_config = {
            "name": "Last Direction",
            "unique_id": "smart_cube_last_direction",
            "state_topic": f"{MQTT_BASE}/last_direction",
            "device": device_info,
            "icon": "mdi:rotate-right"
        }
        topic = f"{HA_DISCOVERY_PREFIX}/sensor/smart_cube_last_direction/config"
        self.publish(topic, json.dumps(direction_config), retain=True)

        log.info("HA MQTT discovery published")
        self.discovery_published = True

    def publish_state(self, state: CubeState):
        self.publish(f"{MQTT_BASE}/solved", "1" if state.solved else "0", retain=True)
        self.publish(f"{MQTT_BASE}/encrypted", "1" if state.encrypted else "0", retain=True)
        self.publish(f"{MQTT_BASE}/raw", state.raw.hex(" "), retain=True)
        self.publish(f"{MQTT_BASE}/decoded", state.decoded.hex(" "), retain=True)
        if state.last_face:
            self.publish(f"{MQTT_BASE}/last_face", state.last_face, retain=True)
        if state.last_direction:
            self.publish(f"{MQTT_BASE}/last_direction", state.last_direction, retain=True)

    def publish_event(self, topic: str, payload: str):
        self.publish(f"{MQTT_BASE}/{topic}", payload, retain=False)

# -----------------------------------------------------------------------------
# Main program
# -----------------------------------------------------------------------------

async def main():
    cfg = load_env_file()
    bridge = MqttBridge(cfg)
    reconnect_delay = 2.0

    # Publish discovery shortly after connect
    while not bridge.connected:
        await asyncio.sleep(0.5)

    await asyncio.sleep(2)  # Let connection settle
    bridge.publish_discovery()

    while True:
        # Discover the cube by scanning for the FE95 service data key.
        device, adv = await discover_target_with_callback(timeout=10.0)
        if not device:
            log.warning("Cube not found, retrying")
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, 30.0)
            continue

        try:
            log.info("Found cube at %s", device.address)
            if adv and adv.service_data:
                log.info("Advertisement service-data keys: %s", ", ".join(adv.service_data.keys()))

            # Connect using the address discovered in this scan.
            disconnect_event = asyncio.Event()

            def on_disconnect(_client):
                disconnect_event.set()

            async with BleakClient(
                device.address,
                timeout=20.0,
                disconnected_callback=on_disconnect,
            ) as client:
                if not client.is_connected:
                    raise RuntimeError("BLE connect failed")

                async def handler(sender: int, data: bytearray):
                    # This runs whenever the cube sends a notification.
                    try:
                        state = decode_packet(bytes(data))
                    except Exception as e:
                        log.warning("Bad packet: %s", e)
                        bridge.publish_event("error", str(e))
                        return

                    bridge.publish_state(state)
                    log.info("State: %s", state.decoded[:16].hex(" "))
                    if state.last_face:
                        log.info("Last move: %s %s", state.last_face, state.last_direction)
                    if state.solved:
                        log.info("Solved")
                        bridge.publish_event("solved_event", "1")

                # Register for notifications on the cube characteristic.
                await client.start_notify(CHAR_UUID, handler)
                log.info("Connected to %s", device.address)
                bridge.publish_event("connected", "1")
                reconnect_delay = 2.0

                # Wait here until the cube disconnects.
                await disconnect_event.wait()

        except Exception as e:
            log.warning("Connection error: %s", e)
            bridge.publish_event("connection_error", str(e))
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, 30.0)

if __name__ == "__main__":
    asyncio.run(main())
