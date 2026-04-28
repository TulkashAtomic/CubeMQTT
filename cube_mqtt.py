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

TARGET_SERVICE_DATA_UUID = "0000fe95-0000-1000-8000-00805f9b34fb"
SERVICE_UUID = "0000aadb-0000-1000-8000-00805f9b34fb"
CHAR_UUID = "0000aadc-0000-1000-8000-00805f9b34fb"

MQTT_BASE = "cube/smart"
MQTT_CLIENT_ID = "cube-pi4"
MQTT_HOST_DEFAULT = "192.168.2.110"
MQTT_PORT_DEFAULT = 1883
HA_DISCOVERY_PREFIX = "homeassistant"

DECRYPTION_KEY = bytes([
    176, 81, 104, 224, 86, 137, 237, 119, 38, 26, 193, 161, 210, 126, 150, 81,
    93, 13, 236, 249, 89, 235, 88, 24, 113, 81, 214, 131, 130, 199, 2, 169, 39, 165, 171, 41
])

SOLUTION = bytes([0x12, 0x34, 0x56, 0x78, 0x33, 0x33, 0x33, 0x33,
                  0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0x00, 0x00])

FACE_NAMES = ["Front", "Bottom", "Right", "Top", "Left", "Back"]

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger("cube")

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
    cfg = Config()
    p = Path(path)
    if not p.exists():
        return cfg
    try:
        text = p.read_text()
    except PermissionError as e:
        raise PermissionError(f"Cannot read {path}.") from e

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
                log.warning("Invalid MQTT_PORT: %s", value)
        elif key == "MQTT_USER":
            cfg.mqtt_user = value
        elif key == "MQTT_PASS":
            cfg.mqtt_pass = value
    return cfg

def get_nibble(data: bytes, i: int) -> int:
    b = data[i // 2]
    return b & 0x0F if i % 2 else (b >> 4) & 0x0F

def decode_packet(data: bytes) -> CubeState:
    if len(data) < 20:
        raise ValueError(f"Packet too short: {len(data)} bytes")

    buf = bytearray(data)
    encrypted = buf[18] == 0xA7

    if encrypted:
        offset1 = get_nibble(buf, 38)
        offset2 = get_nibble(buf, 39)
        if offset1 + 19 >= len(DECRYPTION_KEY) or offset2 + 19 >= len(DECRYPTION_KEY):
            raise ValueError("Decryption offsets out of range")
        for i in range(20):
            buf[i] = (buf[i] + DECRYPTION_KEY[offset1 + i] + DECRYPTION_KEY[offset2 + i]) & 0xFF

    solved = bytes(buf[:16]) == SOLUTION
    last_face = None
    last_direction = None
    face_idx = get_nibble(buf, 32)
    direction_idx = get_nibble(buf, 33)

    if 1 <= face_idx <= 6:
        last_face = FACE_NAMES[face_idx - 1]
        last_direction = "Clockwise" if direction_idx == 1 else "Anti-clockwise"

    return CubeState(raw=data, decoded=bytes(buf), encrypted=encrypted, solved=solved, 
                     last_face=last_face, last_direction=last_direction)

async def discover_target_with_callback(timeout: float = 10.0):
    found = asyncio.Future()
    def detection_callback(device, advertisement_data):
        if advertisement_data.service_data and TARGET_SERVICE_DATA_UUID in advertisement_data.service_data:
            if not found.done():
                found.set_result((device, advertisement_data))

    scanner = BleakScanner(detection_callback)
    await scanner.start()
    try:
        return await asyncio.wait_for(found, timeout=timeout)
    except asyncio.TimeoutError:
        return None, None
    finally:
        await scanner.stop()

# -----------------------------------------------------------------------------
# MQTT bridge
# -----------------------------------------------------------------------------

class MqttBridge:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.connected = False
        self.client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, 
                                  client_id=MQTT_CLIENT_ID)
        if cfg.mqtt_user:
            self.client.username_pw_set(cfg.mqtt_user, cfg.mqtt_pass)

        self.client.on_connect = self.on_connect
        self.client.on_disconnect = self.on_disconnect
        self.client.connect_async(cfg.mqtt_host, cfg.mqtt_port, keepalive=60)
        self.client.loop_start()
        self.discovery_published = False

    def on_connect(self, client, userdata, flags, reason_code, properties=None):
        self.connected = True
        log.info("MQTT connected")
        client.publish(f"{MQTT_BASE}/connected", "1", retain=True)

    def on_disconnect(self, client, userdata, disconnect_flags, reason_code, properties=None):
        self.connected = False
        log.warning("MQTT disconnected")

    def publish(self, topic: str, payload: str, retain: bool = False):
        if self.connected:
            self.client.publish(topic, payload, retain=retain)

    def publish_discovery(self):
        if self.discovery_published: return
        device_info = {"identifiers": ["smart_cube"], "name": "Smart Rubik's Cube", "manufacturer": "Mi"}
        
        sensors = {
            "binary_sensor/smart_cube_solved/config": {"name": "Cube Solved", "state_topic": f"{MQTT_BASE}/solved", "payload_on": "1", "payload_off": "0"},
            "sensor/smart_cube_state/config": {"name": "Cube State", "state_topic": f"{MQTT_BASE}/state"},
            "sensor/smart_cube_last_face/config": {"name": "Last Face", "state_topic": f"{MQTT_BASE}/last_face"},
            "sensor/smart_cube_last_direction/config": {"name": "Last Direction", "state_topic": f"{MQTT_BASE}/last_direction"}
        }
        
        for subtopic, config in sensors.items():
            config["device"] = device_info
            config["unique_id"] = subtopic.replace("/", "_")
            self.publish(f"{HA_DISCOVERY_PREFIX}/{subtopic}", json.dumps(config), retain=True)
        
        self.discovery_published = True

    def publish_state(self, state: CubeState):
        self.publish(f"{MQTT_BASE}/solved", "1" if state.solved else "0", retain=True)
        self.publish(f"{MQTT_BASE}/state", state.decoded.hex(), retain=True)
        self.publish(f"{MQTT_BASE}/json", json.dumps({
            "solved": state.solved, "last_face": state.last_face, "last_direction": state.last_direction
        }), retain=True)
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
    
    while not bridge.connected:
        await asyncio.sleep(0.5)
    bridge.publish_discovery()

    while True:
        device, adv = await discover_target_with_callback(timeout=10.0)
        if not device:
            await asyncio.sleep(5)
            continue

        try:
            disconnect_event = asyncio.Event()
            async with BleakClient(device.address, disconnected_callback=lambda c: disconnect_event.set()) as client:
                async def handler(_, data):
                    try:
                        state = decode_packet(bytes(data))
                        bridge.publish_state(state)
                    except Exception as e:
                        log.warning("Decode error: %s", e)

                await client.start_notify(CHAR_UUID, handler)
                log.info("Cube Connected")
                await disconnect_event.wait()
        except Exception as e:
            log.warning("Connection lost: %s", e)
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(main())