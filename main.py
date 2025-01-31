from rsa import random_primes, key_gen
from encode_decode import encode_message, decode_message

def main():
    original_message = input("Digite a mensagem: ").encode()

    p, q = random_primes()
    public_key, private_key = key_gen(p, q)
    n = public_key[0] 

    signed_message = encode_message(original_message, private_key)
    result = decode_message(signed_message, n // 8, public_key)

    print(result)

