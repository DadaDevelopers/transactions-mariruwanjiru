import json
import struct

def read_varint(data, offset):
    value = data[offset]
    if value < 0xfd:
        return value, offset + 1
    elif value == 0xfd:
        return struct.unpack_from('<H', data, offset + 1)[0], offset + 3
    elif value == 0xfe:
        return struct.unpack_from('<I', data, offset + 1)[0], offset + 5
    else:
        return struct.unpack_from('<Q', data, offset + 1)[0], offset + 9

def decode_transaction(hex_string):
    data = bytes.fromhex(hex_string)
    offset = 0

    # Version (4 bytes, little-endian)
    version = struct.unpack_from('<I', data, offset)[0]
    offset += 4

    # Check for SegWit marker and flag
    marker = data[offset]
    flag = data[offset + 1]
    is_segwit = (marker == 0x00 and flag == 0x01)
    if is_segwit:
        offset += 2

    # Input count
    input_count, offset = read_varint(data, offset)

    # Inputs
    inputs = []
    for _ in range(input_count):
        # Previous TX hash (32 bytes, reversed)
        txid = data[offset:offset+32][::-1].hex()
        offset += 32

        # Previous output index (4 bytes)
        vout = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        # ScriptSig length
        script_len, offset = read_varint(data, offset)

        # ScriptSig
        scriptsig = data[offset:offset+script_len].hex()
        offset += script_len

        # Sequence (4 bytes)
        sequence = struct.unpack_from('<I', data, offset)[0]
        sequence_hex = format(sequence, '08x')
        offset += 4

        inputs.append({
            "txid": txid,
            "vout": vout,
            "script_length": script_len,
            "scriptSig": scriptsig if scriptsig else "(empty)",
            "sequence": sequence_hex
        })

    # Output count
    output_count, offset = read_varint(data, offset)

    # Outputs
    outputs = []
    for _ in range(output_count):
        # Amount (8 bytes, little-endian)
        amount = struct.unpack_from('<q', data, offset)[0]
        offset += 8

        # ScriptPubKey length
        script_len, offset = read_varint(data, offset)

        # ScriptPubKey
        scriptpubkey = data[offset:offset+script_len].hex()
        offset += script_len

        outputs.append({
            "amount_satoshis": amount,
            "script_length": script_len,
            "scriptPubKey": scriptpubkey
        })

    # Witness data
    witness = []
    if is_segwit:
        for _ in range(input_count):
            stack_items, offset = read_varint(data, offset)
            items = []
            for _ in range(stack_items):
                item_len, offset = read_varint(data, offset)
                item = data[offset:offset+item_len].hex()
                offset += item_len
                items.append(item)
            witness.append({"stack_items": stack_items, "data": items})

    # Locktime (4 bytes)
    locktime = struct.unpack_from('<I', data, offset)[0]

    return {
        "version": version,
        "marker": format(marker, '02x') if is_segwit else None,
        "flag": format(flag, '02x') if is_segwit else None,
        "input_count": input_count,
        "inputs": inputs,
        "output_count": output_count,
        "outputs": outputs,
        "witness": witness,
        "locktime": locktime
    }

# Test with provided transaction
tx_hex = "0200000000010131811cd355c357e0e01437d9bcf690df824e9ff785012b6115dfae3d8e8b36c10100000000fdffffff0220a107000000000016001485d78eb795bd9c8a21afefc8b6fdaedf718368094c08100000000000160014840ab165c9c2555d4a31b9208ad806f89d2535e20247304402207bce86d430b58bb6b79e8c1bbecdf67a530eff3bc61581a1399e0b28a741c0ee0220303d5ce926c60bf15577f2e407f28a2ef8fe8453abd4048b716e97dbb1e3a85c01210260828bc77486a55e3bc6032ccbeda915d9494eda17b4a54dbe3b24506d40e4ff43030e00"

decoded = decode_transaction(tx_hex)
print(json.dumps(decoded, indent=2))