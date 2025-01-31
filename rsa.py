import secrets
from math import gcd
from sympy import mod_inverse

def random_primes() -> tuple[int, int]:
    while True:
        primes = []
        num = secrets.randbits(1024) | 1  
        if miller_rabin(num, 40):
            primes.append(num) 
            if len(primes) == 2:
                return primes[0], primes[1] 


def miller_rabin(n: int, k:int) -> bool:
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


def key_gen(p:int, q:int) -> tuple[tuple[int, int], tuple[int,int]] :
    n = p * q
    phi_n = (p-1) * (q-1)

    e = 65537
    if gcd(e, phi_n) != 1:
        while True:
            e = secrets.randbelow(phi_n - 2) + 2
            if gcd(e, phi_n) == 1:
                break

    d = mod_inverse(e, phi_n)

    return (n, e), (n, d)


def rsa_encryption(message: int, key: tuple[int, int]) -> int:
    n, k = key[0], key[1]
    return pow(message, k, n)


def rsa_decryption(encrypted_message: int, key: tuple[int, int]) -> int:
    n, k = key[0], key[1]
    return pow(encrypted_message, k, n)