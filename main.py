import rsa, base64
from encode_decode import encode_message, decode_message
from global_vars import global_vars

def main():
    with open("mensagens/mensagem.txt", "rb") as f:
        mensagem_original = f.read().strip()

    print("=============================================================")
    print("📥 Mensagem lida do arquivo:", mensagem_original)
    print("=============================================================")

    p, q = rsa.random_primes_lib()
    public_key, private_key = rsa.key_gen(p, q)

    signed_message = encode_message(mensagem_original, private_key)

    with open("mensagens/mensagem_assinada.txt", "wb") as f:
        f.write(base64.b64encode(signed_message))

    print("🔹 Mensagem assinada e salva no arquivo.")

    with open("mensagens/mensagem_assinada.txt", "rb") as f:
        signed_message_b64 = f.read()

    signed_message = base64.b64decode(signed_message_b64)

    mensagem_decodificada, assinatura_valida = decode_message(signed_message, public_key)

    print("📤 Mensagem decodificada:", mensagem_decodificada)
    print("🔍 Assinatura válida?", assinatura_valida)

if __name__ == "__main__":
    main()