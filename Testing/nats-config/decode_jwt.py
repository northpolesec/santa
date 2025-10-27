#!/usr/bin/env python3
import base64
import json
import sys

def decode_jwt(jwt_string):
    """Decode a JWT token and print its contents"""
    # JWT has three parts separated by dots: header.payload.signature
    parts = jwt_string.strip().split('.')
    
    if len(parts) != 3:
        print(f"Error: Invalid JWT format. Expected 3 parts, got {len(parts)}")
        return
    
    # Decode header
    header = base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8')
    print("Header:")
    print(json.dumps(json.loads(header), indent=2))
    print()
    
    # Decode payload
    payload = base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8')
    print("Payload:")
    print(json.dumps(json.loads(payload), indent=2))
    print()
    
    # Signature is binary, just show its length
    print(f"Signature: {len(parts[2])} characters")

# Santa account JWT from the config file
santa_jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJJNUhBRUs2SVU2QTdFMkVJQUo3SkdaSUFGT1ZQSloyRVRZWE83STczMzdITDNCV0VLR0FRIiwiaWF0IjoxNzYxMzU1MzkyLCJpc3MiOiJPRE02WjNGVzZBRUNBMktCSkVLNlpIWENTNFZDVFNRQVhSSDZIUklTVkc3NU9IT05FQ1NKT1dVNCIsIm5hbWUiOiJzYW50YSIsInN1YiI6IkFETjRHVUhIS01HTUwyRDJBREVMUFVZRUZGM1FZTkk0RFZONkY0M0pQUDZHSTdWNFNVWVNKVEI0IiwibmF0cyI6eyJsaW1pdHMiOnsic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwiaW1wb3J0cyI6LTEsImV4cG9ydHMiOi0xLCJ3aWxkY2FyZHMiOnRydWUsImNvbm4iOi0xLCJsZWFmIjotMX0sImRlZmF1bHRfcGVybWlzc2lvbnMiOnsicHViIjp7fSwic3ViIjp7fX0sImF1dGhvcml6YXRpb24iOnt9LCJ0eXBlIjoiYWNjb3VudCIsInZlcnNpb24iOjJ9fQ.AQdWYCAAAAlFG3LG1oPLas61F_6kPxQpStbnSOWD2LscVBBCfWirgu8Ae6A7_uQ8DWhe3A1H3c2OtET2jBpVDg"

print("Decoding Santa Account JWT:")
print("=" * 80)
decode_jwt(santa_jwt)

# If you want to decode a JWT passed as argument
if len(sys.argv) > 1:
    print("\n" + "=" * 80)
    print("Decoding JWT from command line:")
    print("=" * 80)
    decode_jwt(sys.argv[1])