# My Solution - Bitcoin Transaction Decoding Assignment

## Overview
This project manually decodes a raw Bitcoin SegWit transaction hex and implements a Python decoder function that can handle both legacy and SegWit transactions.

## Files
- `manual-decode.md` — Task 1: Manual byte-by-byte transaction decode
- `decoder.py` — Task 2: Python function to decode any Bitcoin transaction
- `output.txt` — Program output from running decoder.py

## How to Run
```bash
python3 decoder.py
```

## Key Concepts Used
- **SegWit transaction**: identified by marker `00` and flag `01` after version
- **Little-endian**: Bitcoin stores multi-byte numbers in reverse byte order
- **VarInt**: variable length integer encoding used for counts and lengths
- **Amounts**: stored in satoshis (1 BTC = 100,000,000 satoshis)
- **Witness data**: contains signature and public key for SegWit inputs
- **Byte reversal**: txid is stored in reverse byte order in raw hex

## Transaction Summary
- **Version**: 2
- **Type**: SegWit (P2WPKH)
- **Inputs**: 1
- **Outputs**: 2 (500,000 satoshis and 1,050,700 satoshis)
- **Locktime**: 918339