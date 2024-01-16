import json
import sys

def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        first_colon_index = bencoded_value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        return bencoded_value[first_colon_index+1:].decode()
    elif chr(bencoded_value[0]) == 'i':
        end_index = bencoded_value.find(b'e')
        if end_index == -1:
            raise ValueError("Invalid encoded value")
        return int(bencoded_value[1:end_index])
    elif chr(bencoded_value[0]) == 'l':
        list_items = []
        start_index = 1
        while start_index < len(bencoded_value) and bencoded_value[start_index] != ord('e'):
            if chr(bencoded_value[start_index]).isdigit():
                end_index = bencoded_value.find(b':', start_index)
                length = int(bencoded_value[start_index:end_index])
                start_index = end_index + 1
                list_items.append(bencoded_value[end_index+1:start_index+length].decode())
                start_index += length
            elif chr(bencoded_value[start_index]) == 'i':
                end_index = bencoded_value.find(b'e', start_index)
                list_items.append(int(bencoded_value[start_index+1:end_index]))
                start_index = end_index + 1
            elif chr(bencoded_value[start_index]) == 'l':
                end_index = start_index
                while bencoded_value.count(b'l', start_index, end_index+2) > bencoded_value.count(b'e', start_index, end_index+2):
                    end_index += 1
                list_items.append(decode_bencode(bencoded_value[start_index:end_index+2]))
                start_index = end_index + 2
        return list_items
    else:
        raise NotImplementedError("Only strings, integers and lists are supported at the moment")

def main():
    command = sys.argv[1]

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
