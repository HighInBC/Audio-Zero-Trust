#!/usr/bin/env python3
import argparse
import serial
import time

MAGIC = b"IMPROV"
VERSION = 0x01
TYPE_CURRENT_STATE = 0x01
TYPE_ERROR_STATE = 0x02
TYPE_RPC = 0x03
TYPE_RPC_RESULT = 0x04

CMD_WIFI_SETTINGS = 0x01
CMD_GET_CURRENT_STATE = 0x02
CMD_GET_DEVICE_INFO = 0x03
CMD_GET_WIFI_NETWORKS = 0x04

STATE_MAP = {0x02: "AUTHORIZED", 0x03: "PROVISIONING", 0x04: "PROVISIONED"}
ERR_MAP = {0x00: "NONE", 0x01: "INVALID_RPC", 0x02: "UNKNOWN_RPC", 0x03: "UNABLE_TO_CONNECT", 0x05: "BAD_HOSTNAME", 0xFF: "UNKNOWN"}


def checksum(data: bytes) -> int:
    return sum(data) & 0xFF


def build_packet(pkt_type: int, payload: bytes) -> bytes:
    head = MAGIC + bytes([VERSION, pkt_type, len(payload)]) + payload
    return head + bytes([checksum(head)]) + b"\n"


def build_rpc(cmd: int, data: bytes = b"") -> bytes:
    return bytes([cmd, len(data)]) + data


def build_wifi_payload(ssid: str, password: str) -> bytes:
    s = ssid.encode("utf-8")
    p = password.encode("utf-8")
    return bytes([len(s)]) + s + bytes([len(p)]) + p


def parse_rpc_result(payload: bytes):
    if len(payload) < 2:
        return None
    cmd = payload[0]
    data_len = payload[1]
    data = payload[2:2 + data_len]
    out = []
    i = 0
    while i < len(data):
        ln = data[i]
        i += 1
        out.append(data[i:i + ln].decode("utf-8", "replace"))
        i += ln
    return cmd, out


def read_packets(ser, seconds=10):
    end = time.time() + seconds
    buf = bytearray()
    packets = []
    while time.time() < end:
        d = ser.read(1024)
        if not d:
            continue
        buf.extend(d)
        while True:
            i = buf.find(MAGIC)
            if i < 0:
                if len(buf) > 4096:
                    del buf[:-64]
                break
            if i > 0:
                del buf[:i]
            if len(buf) < 10:
                break
            version = buf[6]
            pkt_type = buf[7]
            ln = buf[8]
            total = 6 + 1 + 1 + 1 + ln + 1
            if len(buf) < total:
                break
            frame = bytes(buf[:total])
            del buf[:total]
            if version != VERSION:
                continue
            calc = checksum(frame[:-1])
            got = frame[-1]
            if calc != got:
                continue
            payload = frame[9:9 + ln]
            packets.append((pkt_type, payload))
    return packets


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="/dev/ttyUSB0")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--ssid", required=True)
    ap.add_argument("--password", required=True)
    args = ap.parse_args()

    ser = serial.Serial(args.port, args.baud, timeout=0.1)

    # Reset via RTS, normal boot via DTR
    ser.setDTR(False)
    ser.setRTS(True)
    time.sleep(0.12)
    ser.setRTS(False)
    time.sleep(1.0)
    ser.reset_input_buffer()

    # Ask for state + device info + scan to ensure protocol is alive
    ser.write(build_packet(TYPE_RPC, build_rpc(CMD_GET_CURRENT_STATE)))
    ser.write(build_packet(TYPE_RPC, build_rpc(CMD_GET_DEVICE_INFO)))
    ser.write(build_packet(TYPE_RPC, build_rpc(CMD_GET_WIFI_NETWORKS)))

    pkts = read_packets(ser, seconds=8)
    print(f"preflight packets: {len(pkts)}")
    for t, p in pkts:
        if t == TYPE_CURRENT_STATE and p:
            print("state:", STATE_MAP.get(p[0], hex(p[0])))
        elif t == TYPE_ERROR_STATE and p:
            print("error:", ERR_MAP.get(p[0], hex(p[0])))
        elif t == TYPE_RPC_RESULT:
            rp = parse_rpc_result(p)
            if rp:
                cmd, vals = rp
                print("rpc_result cmd", hex(cmd), vals)

    # Send wifi credentials
    wifi_data = build_wifi_payload(args.ssid, args.password)
    ser.write(build_packet(TYPE_RPC, build_rpc(CMD_WIFI_SETTINGS, wifi_data)))
    print("sent wifi credentials")

    # Watch for provisioned state and URL/IP response
    provisioned = False
    start = time.time()
    while time.time() - start < 45:
        pkts = read_packets(ser, seconds=2)
        for t, p in pkts:
            if t == TYPE_CURRENT_STATE and p:
                st = p[0]
                print("state:", STATE_MAP.get(st, hex(st)))
                if st == 0x04:
                    provisioned = True
            elif t == TYPE_ERROR_STATE and p:
                print("error:", ERR_MAP.get(p[0], hex(p[0])))
            elif t == TYPE_RPC_RESULT:
                rp = parse_rpc_result(p)
                if rp:
                    cmd, vals = rp
                    print("rpc_result cmd", hex(cmd), vals)
        if provisioned:
            break

    print("RESULT:", "PROVISIONED" if provisioned else "NOT_PROVISIONED")
    ser.close()


if __name__ == "__main__":
    main()
