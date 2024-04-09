import json
import random
import sys
import hashlib
from urllib.parse import urlencode
import requests
import struct
import socket
import math

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

def get_peers(torrent_content):
    url = torrent_content["announce"].decode("utf-8")
    info_encoded = bencode(torrent_content["info"])
    res = requests.get(
        url,
        params={
            "info_hash": hashlib.sha1(info_encoded).digest(),
            "peer_id": "00112233445566778899",
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": torrent_content["info"]["length"],
            "compact": "1",
        },
    )
    decoded_response, _ = decode_bencode(res.content)
    peers_raw = decoded_response["peers"]
    peers = []
    for i in range(0, len(peers_raw), 6):
        ip = ".".join(str(j) for j in peers_raw[i : i + 4])
        port = int.from_bytes(peers_raw[i + 4 : i + 6], byteorder="big")
        peers.append(f"{ip}:{port}")
    return peers

def generate_handshake(torrent_content):
    info_encoded = bencode(torrent_content["info"])
    info_hash = hashlib.sha1(info_encoded).digest()
    handshake = b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"
    handshake += info_hash
    handshake += b"00112233445566778899"
    return handshake

def do_handshake(torrent_content, peer_ip, peer_port):
    handshake = generate_handshake(torrent_content)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((peer_ip, int(peer_port)))
        s.send(handshake)
        response_handshake = s.recv(len(handshake))
    return response_handshake

def download_piece(torrent_file, piece_index, output_file):
    with open(torrent_file, "rb") as f:
        torrent_content = f.read()
    
    decoded_torrent, _ = decode_bencode(torrent_content)
    peers = get_peers(decoded_torrent)
    peer = peers[1]
    peer_ip, peer_port = peer.split(":")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print("Connecting to peer", peer_ip, peer_port)
        s.connect((peer_ip, int(peer_port)))
        handshake = generate_handshake(decoded_torrent)
        s.sendall(handshake)
        response_handshake = s.recv(len(handshake))
        length, msg_type = s.recv(4), s.recv(1)
        if msg_type != b"\x05":
            raise Exception("Expected bitfield message")
        s.recv(int.from_bytes(length, byteorder="big") - 1)
        s.sendall(b"\x00\x00\x00\x01\x02")
        length, msg_type = s.recv(4), s.recv(1)
        while msg_type != b"\x01":
            length, msg_type = s.recv(4), s.recv(1)
        piece_length = decoded_torrent["info"]["piece length"]
        chuck_size = 16 * 1024
        if piece_index == (len(decoded_torrent["info"]["pieces"]) // 20) - 1:
            piece_length = (
                decoded_torrent["info"]["length"] % piece_length
            )
        piece = b""
        for i in range(math.ceil(piece_length / chuck_size)):
            msg_id = b"\x06"
            chunk_index = piece_index.to_bytes(4, byteorder='big')
            chunk_begin = (i * chuck_size).to_bytes(4, byteorder='big')
            if i == math.ceil(piece_length / chuck_size) - 1 and piece_length % chuck_size != 0:
                chunk_length = (piece_length % chuck_size).to_bytes(4, byteorder='big')
            else:
                chunk_length = chuck_size.to_bytes(4, byteorder='big')
            message_length = (1 + len(chunk_index) + len(chunk_begin) + len(chunk_length)).to_bytes(4, byteorder='big')
            request_message = message_length + msg_id + chunk_index + chunk_begin + chunk_length
            s.sendall(request_message)
            print(f"Requesting piece: {int.from_bytes(chunk_index, 'big')}, begin: {int.from_bytes(chunk_begin, 'big')}, length: {int.from_bytes(chunk_length, 'big')}")
            msg = msg_id + chunk_index + chunk_begin + chunk_length
            msg = len(msg).to_bytes(4) + msg
            length, msg_type = int.from_bytes(s.recv(4)), s.recv(1)
            resp_index = int.from_bytes(s.recv(4))
            resp_begin = int.from_bytes(s.recv(4))
            block = b""
            to_get = int.from_bytes(chunk_length)
            while len(block) < to_get:
                block += s.recv(to_get - len(block))
            piece += block
        og_hash = decoded_torrent["info"]["pieces"][piece_index * 20 : piece_index * 20 + 20]
        assert hashlib.sha1(piece).digest() == og_hash
        with open(output_file, "wb") as f:
            f.write(piece)

def download_torrent(torrent_file, output_file):
    with open(torrent_file, "rb") as f:
        torrent_content = f.read()
    
    decoded_torrent, _ = decode_bencode(torrent_content)
    peers = get_peers(decoded_torrent)
    peer = peers[1]
    peer_ip, peer_port = peer.split(":")

    file_length = decoded_torrent["info"]["length"]
    piece_length = decoded_torrent["info"]["piece length"]
    pieces = decoded_torrent["info"]["pieces"]
    num_pieces = len(pieces) // 20

    downloaded_file = b""
    for piece_index in range(num_pieces):
        piece = download_piece1(peer_ip, peer_port, decoded_torrent, piece_index, piece_length, pieces)
        downloaded_file += piece

    with open(output_file, "wb") as f:
        f.write(downloaded_file)

def perform_handshake(s, info_hash, peer_id):
    pstr = b"BitTorrent protocol"
    pstrlen = len(pstr).to_bytes(1, byteorder='big')
    reserved = b'\x00' * 8
    handshake_msg = pstrlen + pstr + reserved + info_hash + peer_id.encode()
    s.send(handshake_msg)
    response = s.recv(68)

def send_interested(s):
    length = b'\x00\x00\x00\x01'
    msg_id = b'\x02'
    s.send(length + msg_id)

def request_piece(s, piece_index, piece_length, block_size=16384):
    piece_data = b''
    num_blocks = math.ceil(piece_length / block_size)
    for i in range(num_blocks):
        block_offset = i * block_size
        block_length = min(piece_length - block_offset, block_size)
        request_msg = struct.pack('>IbIII', 13, 6, piece_index, block_offset, block_length)
        s.send(request_msg)
        piece_data += receive_block(s)
    return piece_data

def receive_block(s):
    block_data = b''
    length_prefix = s.recv(4)
    length = struct.unpack('>I', length_prefix)[0]
    message_id = s.recv(1)
    if message_id == b'\x07':
        index = s.recv(4)
        begin = s.recv(4)
        block_length = length - 9
        while len(block_data) < block_length:
            block_data += s.recv(block_length - len(block_data))
    return block_data

def download_piece1(peer_ip, peer_port, decoded_torrent, piece_index, piece_length, pieces):
    peer_id = '-PY0001-' + ''.join([str(random.randint(0, 9)) for _ in range(12)])
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((peer_ip, int(peer_port)))
        perform_handshake(s, decoded_torrent["info_hash"], peer_id)
        send_interested(s)
        piece_data = request_piece(s, piece_index, piece_length)
        
        expected_hash = pieces[piece_index*20:(piece_index+1)*20]
        if hashlib.sha1(piece_data).digest() != expected_hash:
            raise ValueError("Downloaded piece hash does not match expected hash.")
        
        return piece_data
    
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
        torrent_file = sys.argv[4]
        piece_index = int(sys.argv[5])
        download_piece(torrent_file, piece_index, output_file)
        print(f"Piece {piece_index} downloaded to {output_file}.")
    elif command == "download":
        output_file = sys.argv[3]
        torrent_file = sys.argv[4]
        download_torrent(torrent_file, output_file)
        print(f"Downloaded {torrent_file} to {output_file}.")
    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()