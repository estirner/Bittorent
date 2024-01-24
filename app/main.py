import json
import sys
import hashlib
from urllib.parse import urlencode
import requests
import struct
import socket
import math
import binascii

PEER_ID = b"00112233445566778899"
LEN_OF_PIECE_HASH = 20
BLOCK_SIZE_IN_BYTES = 1 << 14

def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        length = int(bencoded_value[:first_colon_index])
        return bencoded_value[first_colon_index+1:first_colon_index+1+length], bencoded_value[first_colon_index+1+length:]
    elif chr(bencoded_value[0]) == 'i':
        end_index = bencoded_value.find(b'e')
        if end_index == -1:
            raise ValueError("Invalid encoded value")
        return int(bencoded_value[1:end_index]), bencoded_value[end_index+1:]
    elif chr(bencoded_value[0]) == 'l':
        list_values = []
        remaining = bencoded_value[1:]
        while remaining[0] != ord('e'):
            decoded, remaining = decode_bencode(remaining)
            list_values.append(decoded)
        return list_values, remaining[1:]
    elif chr(bencoded_value[0]) == 'd':
        dict_values = {}
        remaining = bencoded_value[1:]
        while remaining[0] != ord('e'):
            key, remaining = decode_bencode(remaining)
            if isinstance(key, bytes):
                key = key.decode()
            value, remaining = decode_bencode(remaining)
            dict_values[key] = value
        return dict_values, remaining[1:]
    else:
        raise NotImplementedError("Only strings, integers, lists, and dictionaries are supported at the moment")

def bencode(data):
    if isinstance(data, dict):
        res = b"d"
        for key, val in data.items():
            res += bencode(key) + bencode(val)
        return res + b"e"
    elif isinstance(data, list):
        res = b"l"
        for val in data:
            res += bencode(val)
        return res + b"e"
    elif isinstance(data, str):
        return f"{len(data)}:{data}".encode()
    elif isinstance(data, bytes):
        return str(len(data)).encode() + b":" + data
    elif isinstance(data, int):
        return f"i{data}e".encode()
    else:
        raise TypeError(f"Type not bencodable: {type(data)} {data}")

def get_content(file_name):
    with open(file_name, mode="rb") as f:
        content = f.read()
        decoded_content = decode_bencode(content)
        return decoded_content

def get_pieces_hex(decoded_content):
    pieces = decoded_content["info"]["pieces"]
    piece_hashes = [
        pieces[i : i + LEN_OF_PIECE_HASH]
        for i in range(0, len(pieces), LEN_OF_PIECE_HASH)
    ]
    piece_hashes_in_hex = [binascii.hexlify(piece).decode() for piece in piece_hashes]
    return piece_hashes_in_hex

def get_hash_bytes(decoded_content):
    info_data = decoded_content["info"]
    info_encoded = bencode(info_data)
    hash_object = hashlib.sha1(info_encoded)
    hash_bytes = hash_object.digest()
    return hash_bytes

def get_peers(decoded_content):
    hash_bytes = get_hash_bytes(decoded_content)
    params = {
        "info_hash": hash_bytes,
        "peer_id": PEER_ID,
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": decoded_content["info"]["length"],
        "compact": 1,

    }

    resp = requests.get(decoded_content["announce"].decode(), params=urlencode(params))
    resp_decoded = decode_bencode(resp.content)
    peers = resp_decoded["peers"]
    peers_decoded = []
    for i in range(0, len(peers), 6):
        peer = peers[i : i + 6]
        ip = ".".join(str(peer[idx]) for idx in range(4))
        port = int(peer[4]) * 16 * 16 + int(peer[5])
        peers_decoded.append(f"{ip}:{port}")
    return peers_decoded

def handshake_socket(hash_bytes, ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, int(port)))
    try:
        handshake_msg = (
            (19).to_bytes(1, "big")
            + b"BitTorrent protocol"
            + (0).to_bytes(8, "big")
            + hash_bytes
            + b"00112233445566778899"
        )
        sock.send(handshake_msg)
        data = sock.recv(len(handshake_msg))
        peer_id_hex = data[48:68].hex()
        return sock, peer_id_hex
    except Exception as e:
        print(e)

def download_piece(output_location, file_name, piece_idx):
    decoded_content = get_content(file_name)
    peers = get_peers(decoded_content)
    peer = peers[0]
    hash_bytes = get_hash_bytes(decoded_content)
    piece_hashes_in_hex = get_pieces_hex(decoded_content)
    ip, port = peer.split(":")

    def receive(sock):
        length = b""
        while not length or not int.from_bytes(length, "big"):
            length = sock.recv(4)
        length = int.from_bytes(length, "big")
        data = sock.recv(length)
        while len(data) < length:
            data += sock.recv(length - len(data))
        msg_id = int(data[0])
        payload = data[1:]
        return msg_id, payload

    def create_request(msg_id, payload):
        msg_length = (len(payload) + 1).to_bytes(4, "big")
        msg_id = msg_id.to_bytes(1, "big")
        data = msg_length + msg_id + payload
        return data

    def parse_incoming_piece(data):
        block_idx = int.from_bytes(data[:4], "big")
        begin_offset = int.from_bytes(data[4:8], "big")
        block_data = data[8:]
        return block_idx, begin_offset, block_data

    sock, peer_id_hex = handshake_socket(hash_bytes, ip, int(port))
    msg_id, data = receive(sock)
    sock.send(create_request(2, b""))
    msg_id, data = receive(sock)
    while msg_id != 1:
        msg_id, data = receive(sock)
    num_pieces = len(decoded_content["info"]["pieces"]) // LEN_OF_PIECE_HASH
    piece_length = decoded_content["info"]["piece length"]
    file_length = decoded_content["info"]["length"]
    if piece_idx == num_pieces - 1:
        piece_length = (file_length % piece_length) or piece_length
    num_blocks = math.ceil(piece_length / BLOCK_SIZE_IN_BYTES)
    piece_data = bytearray()
    for block_idx in range(num_blocks):
        block_offset = block_idx * BLOCK_SIZE_IN_BYTES
        block_length = min(BLOCK_SIZE_IN_BYTES, piece_length - block_offset)
        payload = (
            piece_idx.to_bytes(4, "big")
            + block_offset.to_bytes(4, "big")
            + block_length.to_bytes(4, "big")
        )
        request = create_request(6, payload)
        sock.send(request)
        msg_id, data = receive(sock)
        recv_idx, recv_offset, recv_data = parse_incoming_piece(data)
        piece_data.extend(recv_data)
    expected_piece_hash = piece_hashes_in_hex[piece_idx]
    piece_hash = hashlib.sha1(piece_data).hexdigest()
    if piece_hash != expected_piece_hash:
        raise ValueError("Piece hash does not match expected hash")
    with open(output_location, "wb") as f:
        f.write(piece_data)
    print(f"Piece {piece_idx} downloaded to {output_location}.")

def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()
        decoded_value, _ = decode_bencode(bencoded_value)
        print(json.dumps(decoded_value, default=bytes_to_str))
    elif command == "info":
        with open(sys.argv[2], 'rb') as f:
            bencoded_value = f.read()
        torrent_info, _ = decode_bencode(bencoded_value)
        tracker_url = torrent_info.get('announce', '').decode()
        file_length = torrent_info.get('info', {}).get('length', 0)
        piece_length = torrent_info.get('info', {}).get('piece length', 0)
        pieces = torrent_info.get('info', {}).get('pieces', b'')
        piece_hashes = [pieces[i:i+20].hex() for i in range(0, len(pieces), 20)]
        print(f"Tracker URL: {tracker_url}")
        print(f"Length: {file_length}")
        info_dict = torrent_info.get('info', {})
        bencoded_info = bencode(info_dict)
        info_hash = hashlib.sha1(bencoded_info).hexdigest()
        print(f"Info Hash: {info_hash}")
        print(f"Piece Length: {piece_length}")
        print(f"Piece Hashes: {piece_hashes}")
    elif command == "peers":
        with open(sys.argv[2], 'rb') as f:
            bencoded_value = f.read()
        torrent_info, _ = decode_bencode(bencoded_value)
        tracker_url = torrent_info.get('announce', '').decode()
        info_dict = torrent_info.get('info', {})
        bencoded_info = bencode(info_dict)
        info_hash = hashlib.sha1(bencoded_info).digest()
        params = {
            'info_hash': info_hash,
            'peer_id': '00112233445566778899',
            'port': 6881,
            'uploaded': 0,
            'downloaded': 0,
            'left': torrent_info.get('info', {}).get('length', 0),
            'compact': 1
        }
        response = requests.get(tracker_url, params=params)
        response_dict, _ = decode_bencode(response.content)
        peers = response_dict.get('peers', b'')
        for i in range(0, len(peers), 6):
            ip = '.'.join(str(b) for b in peers[i:i+4])
            port = struct.unpack('!H', peers[i+4:i+6])[0]
            print(f"Peer: {ip}:{port}")
    elif command == "handshake":
        with open(sys.argv[2], 'rb') as f:
            bencoded_value = f.read()
        torrent_info, _ = decode_bencode(bencoded_value)
        info_dict = torrent_info.get('info', {})
        bencoded_info = bencode(info_dict)
        info_hash = hashlib.sha1(bencoded_info).digest()
        peer_id = '00112233445566778899'
        ip_port = sys.argv[3].split(':')
        ip = ip_port[0]
        port = int(ip_port[1])
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            protocol_name = 'BitTorrent protocol'
            handshake = struct.pack(f'>B{len(protocol_name)}s8x20s20s', len(protocol_name), protocol_name.encode(), info_hash, peer_id.encode())
            s.sendall(handshake)
            data = s.recv(68)
            peer_id_received = data[-20:]
            print(f"Peer ID: {peer_id_received.hex()}")
    elif command == "download_piece":
        flag = sys.argv[2]
        file_location = sys.argv[3]
        file_name = sys.argv[4]
        piece_idx = int(sys.argv[5])
        download_piece(file_location, file_name, piece_idx)
    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()