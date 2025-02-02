import hashlib
from typing import Callable, Tuple
from global_vars import global_vars

def sign_message(
    message: bytes, 
    rsa_encryption: Callable[[int, Tuple[int, int]], int], 
    private_key: Tuple[int, int], 
    hash = hashlib.sha3_256
) -> bytes:
    """
    Assina uma mensagem calculando seu hash e criptografando-o com a chave privada RSA.

    Args:
        message (bytes): A mensagem a ser assinada.
        rsa_encryption (Callable[[int, Tuple[int, int]], int]): Função RSA para criptografar o hash da mensagem.
        private_key (Tuple[int, int]): A chave privada (n, d).
        hash: Função de hash usada para calcular o hash da mensagem (padrão: hashlib.sha3_256).

    Returns:
        bytes: A assinatura da mensagem.
    """
    print(f"🔹 Assinando mensagem: {message}") 

    message_hash = int.from_bytes(hash(message).digest(), byteorder="big")
    global_vars["Assinatura antes do RSA"] = message_hash

    print(f"🔹 Assinatura da mensagem antes do RSA: {message_hash}")  
    

    signature = rsa_encryption(message_hash, private_key)
    signed_bytes = signature.to_bytes((private_key[0].bit_length() + 7) // 8, byteorder="big")

    global_vars["Assinatura depois do RSA"] = int.from_bytes(signed_bytes)
    print(f"🔹 Assinatura gerada pós RSA: {int.from_bytes(signed_bytes)}")  

    return signed_bytes



def verify_signature(
    message: bytes, 
    signature: bytes, 
    rsa_decryption: Callable[[int, Tuple[int, int]], int], 
    public_key: Tuple[int, int], 
    hash: Callable = hashlib.sha3_256
) -> bool:
    """
    Verifica a assinatura de uma mensagem comparando o hash da mensagem com o hash descriptografado da assinatura.

    Args:
        message (bytes): A mensagem cuja assinatura deve ser verificada.
        signature (bytes): A assinatura a ser verificada.
        rsa_decryption (Callable[[int, Tuple[int, int]], int]): Função RSA para descriptografar a assinatura.
        public_key (Tuple[int, int]): A chave pública (n, e).
        hash: Função de hash usada para calcular o hash da mensagem (padrão: hashlib.sha3_256).

    Returns:
        bool: True se a assinatura for válida, False caso contrário.
    """



    message_hash = int.from_bytes(hash(message).digest(), byteorder="big")
    print(f"🔹 Assinatura da mensagem original antes do RSA: {message_hash}")  # Debug


    decrypted_hash = rsa_decryption(int.from_bytes(signature), public_key)
    print(f"🔹 Hash descriptografado da assinatura: {decrypted_hash}")  # Debug
    
    return message_hash == decrypted_hash