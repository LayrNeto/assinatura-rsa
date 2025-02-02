import hashlib
import secrets

def mask_generator(seed: bytes, key_length: int, hash = hashlib.sha3_256) -> bytes:
    """
    Gera uma máscara de comprimento especificado usando uma função de hash e uma semente.

    Args:
        seed (bytes): Semente usada para a geração da máscara.
        key_length (int): Comprimento desejado da máscara em bytes.
        hash: Função de hash usada para gerar a máscara (padrão: hashlib.sha3_256).

    Returns:
        bytes: Máscara gerada de comprimento especificado.
    """

    mask = b""
    counter = 0

    while len(mask) < key_length:
        counter_bytes = counter.to_bytes(4, "big")
        mask += hash(seed + counter_bytes).digest()
        counter += 1

    return mask[:key_length]

def oaep_encode(block_message: bytes, key_length: int, hash = hashlib.sha3_256) -> bytes:
    """
    Aplica padding em um bloco de uma mensagem usando OAEP (Optimal Asymmetric Encryption Padding).

    Args:
        block_message (bytes): A mensagem em blocos a ser codificada.
        key_length (int): Comprimento da chave RSA em bits.
        hash: Função de hash usada para o padding (padrão: hashlib.sha3_256).

    Returns:
        bytes: A mensagem preenchida com OAEP.
    
    Raises:
        ValueError: Se o bloco de mensagem for maior do que o OAEP pode aceitar.
    """

    hash_len = hash().digest_size
    block_len = (key_length + 7) // 8

    padding_len = block_len - len(block_message) - hash_len - 2
    if padding_len < 0:
        raise ValueError("Bloco maior do que o OAEP aceita.")

    if padding_len > (2**31 - 1):
        print(f"padding_len = {padding_len}")  # Debug
        raise OverflowError("padding_len é muito grande para ser processado.")
    
    padded_block = (b"\x00" * padding_len) + b"\x01" + block_message
    seed = secrets.token_bytes(hash_len)

    block_mask = mask_generator(seed, len(padded_block))
    masked_block = bytes(x ^ y for x, y in zip(block_mask, padded_block))

    seed_mask = mask_generator(masked_block, hash_len)
    masked_seed = bytes(x ^ y for x, y in zip(seed, seed_mask))  

    return b'\x00' + masked_seed + masked_block
 

def oaep_decode(encoded_message: bytes, key_length: int, hash = hashlib.sha3_256) -> bytes:
    """
    Decodifica uma mensagem preenchida com OAEP (Optimal Asymmetric Encryption Padding).

    Args:
        encoded_message (bytes): A mensagem codificada com OAEP.
        key_length (int): Comprimento da chave RSA em bits.
        hash: Função de hash usada para o padding (padrão: hashlib.sha3_256).

    Returns:
        bytes: A mensagem decodificada.

    Raises:
        ValueError: Se a mensagem codificada não contiver o delimitador 0x01.
    """

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