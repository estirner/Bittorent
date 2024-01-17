import json
import sys
import hashlib

def decode_bencode(bencoded_value):
    if bencoded_value[0:1].isdigit():
        length, remaining = bencoded_value.split(b':', 1)
        return remaining[:int(length)], remaining[int(length):]
    elif bencoded_value[0:1] == b'i':
        value, remaining = bencoded_value[1:].split(b'e', 1)
        return int(value), remaining
    elif bencoded_value[0:1] == b'l':
        list_values = []
        remaining = bencoded_value[1:]
        while remaining and remaining[0:1] != b'e':
            decoded, remaining = decode_bencode(remaining)
            list_values.append(decoded)
        return list_values, remaining[1:] if remaining else remaining
    elif bencoded_value[0:1] == b'd':
        dict_values = {}
        remaining = bencoded_value[1:]
        while remaining and remaining[0:1] != b'e':
            key, remaining = decode_bencode(remaining)
            if isinstance(key, bytes):
                key = key.decode()
            value, remaining = decode_bencode(remaining)
            dict_values[key] = value
        return dict_values, remaining[1:] if remaining else remaining
    else:
        raise ValueError("Invalid bencoded value")

def bencode(value):
    if isinstance(value, int):
        return f"i{value}e".encode()
    elif isinstance(value, bytes):
        return f"{len(value)}:{value}".encode()
    elif isinstance(value, list):
        return b"l" + b"".join(bencode(v) for v in value) + b"e"
    elif isinstance(value, dict):
        if not all(isinstance(k, bytes) for k in value.keys()):
            print(f"Dictionary keys are not bytes: {value}")
        try:
            return b"d" + b"".join(bencode(k) + bencode(v) for k, v in sorted(value.items())) + b"e"
        except TypeError as e:
            for k, v in value.items():
                if not isinstance(v, (int, bytes, list, dict)):
                    print(f"Unhandled type for key {k}: {type(v)}, value: {v}")
            raise e
    else:
        print(f"Unhandled type: {type(value)}, value: {value}")
        raise TypeError(f"Type not serializable: {type(value)}")

def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        decoded_value, _ = decode_bencode(bencoded_value)
        print(json.dumps(decoded_value, default=bytes_to_str))  # Removed indent argument
    elif command == "info":
        with open(sys.argv[2], 'rb') as f:
            bencoded_value = f.read()
        torrent_info, _ = decode_bencode(bencoded_value)
        tracker_url = torrent_info.get(b'announce', b'').decode()
        file_length = torrent_info.get(b'info', {}).get(b'length', 0)
        print(f"Tracker URL: {tracker_url}")
        print(f"Length: {file_length}")
        if b'info' in torrent_info:
            try:
                info_bencoded = bencode(torrent_info[b'info'])
                info_hash = hashlib.sha1(info_bencoded).hexdigest()
                print(f"Info hash: {info_hash}")
            except Exception as e:
                print(f"Error when calculating info hash: {e}")
                print(f"Info section: {torrent_info[b'info']}")
        else:
            print("The torrent file does not contain an 'info' section.")

if __name__ == "__main__":
    main()
