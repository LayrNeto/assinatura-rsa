import oaep, signature, oaep, rsa

def encode_message(message, private_key):
    blocks = []
    max_block_bytes = 190
    
    sign = signature.sign_message(message, rsa.rsa_encryption, private_key)

    while len(message) > max_block_bytes:
        blocks.append(message[:max_block_bytes])
        message = message[max_block_bytes:]
    if message:
        blocks.append(message)

    padded_blocks = []
    for block in blocks:
        aux = oaep.oaep_encode(block, private_key[0])
        padded_blocks.append(aux)

    return b" ".join(padded_blocks) + b"|" + sign

def decode_message(signed_message, block_len, public_key):
    delimiter = signed_message.find(b"|")
    message, sign = signed_message[:delimiter], signed_message[delimiter+1:]

    padded_blocks = []
    while len(message) > block_len:
        padded_blocks.append(message[:block_len])
        message = message[block_len:]
    if message:
        padded_blocks.append(message)

    messages = []
    for block in padded_blocks:
        aux = oaep.oaep_decode(block, block_len * 8)
        messages.append(aux)

    mensagem = b"".join(messages).decode()

    booleano = signature.verify_signature(mensagem, rsa.rsa_decryption, public_key)

    return booleano
