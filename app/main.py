import json
import sys
import hashlib

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

def bencode(value):
    if isinstance(value, int):
        return f"i{value}e".encode()
    elif isinstance(value, bytes):
        return f"{len(value)}:{value}".encode()
    elif isinstance(value, list):
        return b"l" + b"".join(bencode(v) for v in value) + b"e"
    elif isinstance(value, dict):
        return b"d" + b"".join(bencode(k) + bencode(v) for k, v in sorted(value.items())) + b"e"
    else:
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
        print(json.dumps(decoded_value, default=bytes_to_str))
    elif command == "info":
        with open(sys.argv[2], 'rb') as f:
            bencoded_value = f.read()
        torrent_info, _ = decode_bencode(bencoded_value)
        tracker_url = torrent_info.get('announce', '').decode()
        file_length = torrent_info.get('info', {}).get('length', 0)
        print(f"Tracker URL: {tracker_url}")
        print(f"Length: {file_length}")
        info_hash = hashlib.sha1(bencode(torrent_info['info'])).hexdigest()
        print(f"Info hash: {info_hash}")
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
