import hashlib

def sign_message(message: bytes, rsa_encryption: function, private_key: tuple[int, int], hash = hashlib.sha3_256) -> bytes:
    n = private_key[0]
    message_hash = int.from_bytes(hash(message).digest(), byteorder= "big")

    signature = rsa_encryption(message_hash, private_key)
    
    return signature.to_bytes((n.bit_length() + 7) // 8, byteorder= "big")


def verify_signature(signed_message: bytes, rsa_decryption: function, public_key: tuple[int, int], hash = hashlib.sha3_256) -> bool:
    n = public_key[0]
    signature_len = (n.bit_length() + 7) // 8

    message = signed_message[:-signature_len]
    signature = signed_message[-signature_len:]

    message_hash = int.from_bytes(hash(message).digest(), byteorder= "big")
    descrypted_hash = rsa_decryption(int.from_bytes(signature, byteorder="big"), public_key)

    return message_hash == descrypted_hash