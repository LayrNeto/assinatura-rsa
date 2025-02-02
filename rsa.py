import secrets
from math import gcd
from sympy import mod_inverse, randprime
from typing import Tuple
from global_vars import global_vars

def random_primes_lib():
    p = randprime(2**1023, 2**1024)  
    q = randprime(2**1023, 2**1024)

    global_vars["p"] = p
    global_vars["q"] = q

    return p, q


def random_primes() -> Tuple[int, int]:
    """
    Gera dois números primos grandes, cada um com pelo menos 1024 bits.

    Returns:
        Tuple[int, int]: Dois números primos grandes (p, q).
    """

    while True:
        primes = []
        num = secrets.randbits(1024) | 1 

        if miller_rabin(num, 40):
            primes.append(num)
            if len(primes) == 2:

                global_vars["p"] = primes[0]
                global_vars["q"] = primes[1]

                return primes[0], primes[1]



def miller_rabin(n: int, k: int) -> bool:
    """
    Teste de primalidade Miller-Rabin para verificar se um número é primo.

    Args:
        n (int): O número a ser testado.
        k (int): Número de iterações para melhorar a precisão do teste.

    Returns:
        bool: True se n é provavelmente primo, False caso contrário.
    """

    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        aux = pow(a, d, n)

        if aux == 1 or aux == n - 1:
            continue

        for _ in range(r - 1):
            aux = pow(aux, 2, n)
            if aux == n - 1:
                break
        else:
            return False    
    return True



def key_gen(p: int, q: int) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Gera um par de chaves RSA (pública e privada) a partir de dois números primos.

    Args:
        p (int): Primeiro número primo.
        q (int): Segundo número primo.

    Returns:
        Tuple[Tuple[int, int], Tuple[int, int]]: 
            Par de chaves RSA (chave pública (n, e) e chave privada (n, d)).
    """

    n = p * q
    phi_n = (p - 1) * (q - 1)

    global_vars["n"] = n
    global_vars["phi_n"] = phi_n

    e = 65537
    if gcd(e, phi_n) != 1:
        while True:
            e = secrets.randbelow(phi_n - 2) + 2
            if gcd(e, phi_n) == 1:
                break

    d = mod_inverse(e, phi_n)

    global_vars["e"] = e
    global_vars["d"] = d

    return (n, e), (n, d)


def rsa_encryption(message: int, key: Tuple[int, int]) -> int:
    """
    Criptografa uma mensagem usando uma chave RSA.

    Args:
        message (int): A mensagem a ser criptografada.
        key (Tuple[int, int]): A chave pública ou privada (n, k).

    Returns:
        int: A mensagem criptografada.
    """

    n, k = key[0], key[1]
    return pow(message, k, n)



def rsa_decryption(encrypted_message: int, key: Tuple[int, int]) -> int:
    """
    Descriptografa uma mensagem criptografada usando uma chave RSA.

    Args:
        encrypted_message (int): A mensagem criptografada a ser descriptografada.
        key (Tuple[int, int]): A chave privada ou pública (n, k).

    Returns:
        int: A mensagem descriptografada.
    """

    n, k = key[0], key[1]
    return pow(encrypted_message, k, n)