import hashlib
import secrets

def mask_generator(seed, key_length, hash = hashlib.sha3_256):
    mask = b""
    counter = 0

    while len(mask) < key_length:
        counter_bytes = counter.to_bytes(4, "big")
        mask += hash(seed + counter_bytes).digest()
        counter += 1

    return mask[:key_length]


def oaep_encode(block_message, key_length, hash = hashlib.sha3_256):
    hash_len = hash().digest_size
    block_len = key_length // 8

    padding_len = block_len - len(block_message) - hash_len - 2
    if padding_len < 0:
        raise ValueError("Bloco maior do que o OAEP aceita.")

    padded_block = (b"\x00" * padding_len) + b"\x01" + block_message
    seed = secrets.token_bytes(hash_len)

    block_mask = mask_generator(seed, len(padded_block))
    masked_block = bytes(x ^ y for x, y in zip(block_mask, padded_block))

    seed_mask = mask_generator(masked_block, hash_len)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))  

    return b'\x00' + masked_seed + masked_block 


def oaep_decode(encoded_message, key_length, hash = hashlib.sha3_256):
    hash_len = hash().digest_size
    block_len = key_length // 8

    masked_seed, masked_block = encoded_message[1:hash_len+1], encoded_message[hash_len+1:]

    seed_mask = mask_generator(masked_block, hash_len)
    seed = bytes(x ^ y for x, y in zip(seed_mask, masked_seed))

    block_mask = mask_generator(seed, len(masked_block))
    padded_block = bytes(x ^ y for x, y in zip(block_mask, masked_block))

    padding_index = padded_block.find(b"\x01")
    if padding_index == -1:
        raise ValueError("OAEP inválido, não possui delimitador 0x01")

    return padded_block[padding_index+1:]