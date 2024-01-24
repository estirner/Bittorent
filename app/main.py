import json
import sys
import hashlib
from urllib.parse import urlencode
import requests
import struct
import socket
import math

def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        return decode_bencode_string(bencoded_value)
    elif chr(bencoded_value[0]) == 'i':
        end_index = bencoded_value.find(b'e')
        if end_index == -1:
            raise ValueError("Invalid encoded value")
        return int(bencoded_value[1:end_index]), bencoded_value[end_index+1:]
    elif chr(bencoded_value[0]) == 'l':
        return decode_bencode_list(bencoded_value)
    elif chr(bencoded_value[0]) == 'd':
        return decode_bencode_dict(bencoded_value)

def bencode(data):
    if isinstance(data, str):
        return f"{len(data)}:{data}".encode()
    elif isinstance(data, bytes):
        return f"{len(data)}:".encode() + data
    elif isinstance(data, int):
        return f"i{data}e".encode()
    elif isinstance(data, list):
        return b"l" + b"".join(bencode(item) for item in data) + b"e"
    elif isinstance(data, dict):
        encoded_dict = b"".join(bencode(key) + bencode(value) for key, value in sorted(data.items()))
        return b"d" + encoded_dict + b"e"
    else:
        raise TypeError(f"Type not serializable: {type(data)}")
    
def decode_bencode_string(bencoded_value):
    first_colon_index = bencoded_value.find(b":")
    if first_colon_index == -1:
        raise ValueError("Invalid encoded value")
    length = first_colon_index + int(bencoded_value[:first_colon_index]) + 1
    return bencoded_value[first_colon_index + 1 : length], length

def decode_bencode_list(bencoded_value):
    index, result = 1, []
    while bencoded_value[index] != ord("e"):
        decoded_value, length = decode_bencode(bencoded_value[index:])
        index += length
        result.append(decoded_value)
    return result, index + 1

def decode_bencode_dict(bencoded_value):
    index, result = 1, {}
    while bencoded_value[index] != ord("e"):
        key, length = decode_bencode(bencoded_value[index:])
        index += length
        value, length = decode_bencode(bencoded_value[index:])
        index += length
        result[key.decode()] = value
    return result, index + 1

def extract_info_hash(bencoded_value):
    _, bencoded_value_from_info = bencoded_value.split(b"info")
    _, dict_length = decode_bencode_dict(bencoded_value_from_info)
    return bencoded_value_from_info[:dict_length]

def extract_pieces_hashes(pieces_hashes):
    index, result = 0, []
    while index < len(pieces_hashes):
        result.append(pieces_hashes[index : index + 20].hex())
        index += 20
    return result

def get_peers(decoded_data, info_hash):
    params = {
        "info_hash": info_hash,
        "peer_id": "PC0001-7694471987235",
        "port": 6881,
        "uploaded": 0,
        "downloaded": 0,
        "left": decoded_data["info"]["length"],
        "compact": 1,
    }
    response = requests.get(decoded_data["announce"].decode(), params=params)
    return decode_peers(decode_bencode(response.content)[0]["peers"])

def decode_peers(peers):
    index, result = 0, []
    while index < len(peers):
        ip = ".".join([str(peers[index + offset]) for offset in range(4)])
        port = peers[index + 4] * 256 + peers[index + 5]
        result.append(f"{ip}:{port}")
        index += 6
    return result

def get_peer_id(ip, port, info_hash):
    protocol_name_length = struct.pack(">B", 19)
    protocol_name = b"BitTorrent protocol"
    reserved_bytes = b"\x00" * 8
    peer_id = b"PC0001-7694471987235"
    payload = (
        protocol_name_length + protocol_name + reserved_bytes + info_hash + peer_id
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((ip, port))
        sock.sendall(payload)
        response = sock.recv(1024)
        return response[48:].hex()
    finally:
        sock.close()

def download_piece(decoded_data, info_hash, piece_index, output_file):
    peers = get_peers(decoded_data, info_hash)
    peer_ip, peer_port = peers[0].split(":")
    peer_port = int(peer_port)
    get_peer_id(peer_ip, peer_port, info_hash)
    protocol_name_length = struct.pack(">B", 19)
    protocol_name = b"BitTorrent protocol"
    reserved_bytes = b"\x00" * 8
    peer_id = b"PC0001-7694471987235"
    payload = (
        protocol_name_length + protocol_name + reserved_bytes + info_hash + peer_id
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((peer_ip, peer_port))
        sock.sendall(payload)
        response = sock.recv(68)
        message = receive_message(sock)
        while int(message[4]) != 5:
            message = receive_message(sock)
        interested_payload = struct.pack(">IB", 1, 2)
        sock.sendall(interested_payload)
        message = receive_message(sock)
        while int(message[4]) != 1:
            message = receive_message(sock)
        file_length = decoded_data["info"]["length"]
        total_number_of_pieces = len(
            extract_pieces_hashes(decoded_data["info"]["pieces"])
        )
        default_piece_length = decoded_data["info"]["piece length"]
        if piece_index == total_number_of_pieces - 1:
            piece_length = file_length - (default_piece_length * piece_index)
        else:
            piece_length = default_piece_length
        number_of_blocks = math.ceil(piece_length / (16 * 1024))
        data = bytearray()
        for block_index in range(number_of_blocks):
            begin = 2**14 * block_index
            print(f"begin: {begin}")
            block_length = min(piece_length - begin, 2**14)
            print(
                f"Requesting block {block_index + 1} of {number_of_blocks} with length {block_length}"
            )
            request_payload = struct.pack(
                ">IBIII", 13, 6, piece_index, begin, block_length
            )
            print("Requesting block, with payload:")
            print(request_payload)
            print(struct.unpack(">IBIII", request_payload))
            print(int.from_bytes(request_payload[:4]))
            print(int.from_bytes(request_payload[4:5]))
            print(int.from_bytes(request_payload[5:9]))
            print(int.from_bytes(request_payload[17:21]))
            sock.sendall(request_payload)
            message = receive_message(sock)
            data.extend(message[13:])
        with open(output_file, "wb") as f:
            f.write(data)
    finally:
        sock.close()
    return True

def receive_message(s):
    length = s.recv(4)
    while not length or not int.from_bytes(length):
        length = s.recv(4)
    message = s.recv(int.from_bytes(length))
    while len(message) < int.from_bytes(length):
        message += s.recv(int.from_bytes(length) - len(message))
    return length + message

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
            output_file = sys.argv[3]
            piece_index = int(sys.argv[5])
            torrent_file = sys.argv[4]
            with open(torrent_file, "rb") as f:
                torrent_data = f.read()
            decoded_data = decode_bencode(torrent_data)[0]
            if download_piece(
                decoded_data,
                hashlib.sha1(extract_info_hash(torrent_data)).digest(),
                piece_index,
                output_file,
            ):
                print(f"Piece {piece_index} downloaded to {output_file}.")
            else:
                raise RuntimeError("Failed to download piece")
    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()