import json
import sys
import hashlib
import requests
import struct
import socket

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
    
def handshake(peer_ip, peer_port, info_hash, peer_id):
    pstrlen = b'\x13'
    pstr = b'BitTorrent protocol'
    reserved = b'\x00' * 8
    payload = pstrlen + pstr + reserved + info_hash + peer_id.encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((peer_ip, peer_port))
    sock.send(payload)
    return sock

def send_interested(sock):
    length = struct.pack('>I', 1)
    message_id = struct.pack('>B', 2)
    sock.send(length + message_id)

def recv_message(sock):
    length_prefix = struct.unpack('>I', sock.recv(4))[0]
    message_id = struct.unpack('>B', sock.recv(1))[0]
    payload = sock.recv(length_prefix - 1)
    return message_id, payload

def send_request(sock, index, begin, length):
    length_prefix = struct.pack('>I', 13)
    message_id = struct.pack('>B', 6)
    payload = struct.pack('>III', index, begin, length)
    sock.send(length_prefix + message_id + payload)

def recv_piece(sock):
    _, payload = recv_message(sock)
    index, begin = struct.unpack('>II', payload[:8])
    block = payload[8:]
    return index, begin, block

def download_piece(torrent_info, piece_index, output_path):
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
        sock = handshake(ip, port, info_hash, params['peer_id'])
        send_interested(sock)
        while True:
            message_id, _ = recv_message(sock)
            if message_id == 1:
                break
        file_length = torrent_info.get('info', {}).get('length', 0)
        piece_length = torrent_info.get('info', {}).get('piece length', 0)
        num_pieces = file_length // piece_length
        if piece_index == num_pieces - 1:
            piece_length = file_length % piece_length
        blocks_per_piece = piece_length // (16 * 1024)
        last_block_length = piece_length % (16 * 1024)
        piece = b''
        for block_index in range(blocks_per_piece):
            send_request(sock, piece_index, block_index * (16 * 1024), 16 * 1024)
            _, _, block = recv_piece(sock)
            piece += block
        if last_block_length > 0:
            send_request(sock, piece_index, blocks_per_piece * (16 * 1024), last_block_length)
            _, _, block = recv_piece(sock)
            piece += block
        with open(output_path, 'wb') as f:
            f.write(piece)
        print(f"Piece {piece_index} downloaded to {output_path}.")

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
        with open(sys.argv[4], 'rb') as f:
            bencoded_value = f.read()
        torrent_info, _ = decode_bencode(bencoded_value)
        piece_index = int(sys.argv[5])
        output_path = sys.argv[3]
        download_piece(torrent_info, piece_index, output_path)
    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()