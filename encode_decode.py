import signature, oaep, rsa
from typing import Tuple

def encode_message(message: bytes, private_key: Tuple[int, int]) -> bytes:
    """
    Cria uma assinatura, divide a mensagem, e aplica OAEP aos blocos.

    Args:
        message (bytes): A mensagem a ser codificada.
        private_key (Tuple[int, int]): A chave privada RSA (n, d) usada para assinar e criptografar.

    Returns:
        bytes: A mensagem codificada e assinada.
    """
    blocks = []
    max_block_bytes = 190

    sign = signature.sign_message(message, rsa.rsa_encryption, private_key)

    print("=============================================================")
    while len(message) > max_block_bytes:
        blocks.append(message[:max_block_bytes])
        message = message[max_block_bytes:]
    if message:
        blocks.append(message)

    padded_blocks = []
    for block in blocks:
        aux = oaep.oaep_encode(block, private_key[0].bit_length())
        padded_blocks.append(aux)

    return b"".join(padded_blocks) + b"|" + sign



def decode_message(signed_message: bytes, public_key: Tuple[int, int]) -> Tuple[str, bool]:
    """
    Decodifica uma mensagem codificada, remove OAEP, e verifica a assinatura;

    Args:
        signed_message (bytes): A mensagem codificada e assinada.
        public_key (Tuple[int, int]): A chave pública RSA (n, e) usada para verificar a assinatura.

    Returns:
        Tuple[bytes, bool]: A mensagem decodificada e um booleano indicando a validade da assinatura.
    """

    print("=============================================================")

    block_len = (public_key[0].bit_length() + 7) // 8 

    try:
        message, sign = signed_message.rsplit(b"|", 1) 
    except ValueError:
        return b"", False

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

    mensagem = b"".join(messages)

    print(f"🔹 Mensagem extraída: {mensagem}")  # Debug
    print(f"🔹 Assinatura extraída: {int.from_bytes(sign)}")  # Debug
    print("=============================================================")
    booleano = signature.verify_signature(mensagem, sign, rsa.rsa_decryption, public_key)

    return mensagem.decode(), booleano
