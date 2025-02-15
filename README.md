# Gerador e verificador de assinaturas RSA em arquivos

* [Introdução](#introdução)
* [Fundamentação Teórica](#fundamentação-teórica)
    * [RSA](#rsa-rivest-shamir-adleman)
    * [OAEP](#oaep-optimal-asymmetric-encryption-padding)
    * [Assinatura Digital](#assinatura-digital)
* [Implementação](#implementação)
    * [RSA](#rsa)
    * [OAEP](#oaep)
    * [Signature](#signature)
    * [Encode Decode](#encode-decode)
    * [Main](#main)
* [Conclusão](#conclusão)

## Introdução 

Este projeto implementa um sistema de assinatura digital de arquivos, utilizando os seguintes algoritmos:

- **RSA**: Responsável pela criptografia e decriptografia da assinatura.
- **SHA3-256**: Utilizado para gerar um hash único do conteúdo do arquivo.
- **OAEP**: Aplicado como um esquema de padding para garantir segurança adicional.

O objetivo do projeto não é criptografar o conteúdo do arquivo, mas sim gerar uma assinatura digital baseada no hash do arquivo. Dessa forma, é possível verificar a autenticidade e integridade do conteúdo sem ocultá-lo, garantindo que qualquer modificação no arquivo original resulte em uma assinatura inválida.


## Fundamentação Teórica

### RSA (Rivest-Shamir-Adleman)

O RSA é um algoritmo de criptografia assimétrica que utiliza um par de chaves — **pública** e **privada** — para garantir segurança, baseando-se na dificuldade da fatoração de grandes números primos.

#### 📌 Geração das Chaves

1. Escolha de dois números primos grandes aleatórios **p** e **q**.
2. Cálculo de **n = p × q** e **ϕ(n) = (p − 1) × (q − 1)**.
3. Escolha de um expoente público **e**, tal que **1 < e < ϕ(n)** e **gcd(e, ϕ(n)) = 1** (primos entre si).
4. Cálculo do expoente privado **d**, tal que **d ≡ e⁻¹ (mod ϕ(n))**.
5. O resultado final gera:
   - **Chave Pública**: {n, e}
   - **Chave Privada**: {n, d}

#### 🔐 Processo de Criptografia e Descriptografia

1. **Criptografia:**  
   - A mensagem \( M \) é convertida para um valor numérico e criptografada como:  
     \[
     C = M<sup>e</sup> mod n
     \]

2. **Descriptografia:**  
   - O texto cifrado \( C \) é recuperado através da chave privada:  
     \[
     M = C<sup>d</sup> mod n
     \]

⚠ **Importante:** No RSA, a ordem dos expoentes \( e \) e \( d \) pode ser invertida dependendo do objetivo da criptografia. No contexto deste projeto, **o RSA é utilizado para assinar digitalmente o hash da mensagem** garantindo sua autenticidade. Nesse caso, a **assinatura é gerada com \( d \) e verificada com \( e \)**, em vez da ordem convencional usada para criptografar mensagens.



### OAEP (Optimal Asymmetric Encryption Padding)

O OAEP é um esquema de padding utilizado para evitar ataques determinísticos ao RSA, garantindo que mensagens idênticas resultem em criptogramas diferentes. Ele é aplicado em **todos os blocos da mensagem** antes da criptografia RSA.

#### 📌 Estrutura do OAEP

O bloco final contém os seguintes elementos:
- **Byte 0x00** → Indica o início do bloco.
- **Seed aleatória** → Usada para gerar a máscara.
- **Função Geradora de Máscara (MGF)** → Responsável por derivar máscaras a partir da seed.
- **Label (opcional)** → Um valor adicional que pode ser usado para reforçar a segurança.
- **Padding** → Preenchimento de bytes, sempre finalizando com um **delimitador 0x01**.
- **Bloco original** → O conteúdo real da mensagem a ser criptografado.

#### 🔄 Processo de Codificação OAEP

1. O bloco recebe padding e um delimitador `0x01`.
2. A **seed** aleatória é utilizada para gerar uma máscara via MGF.
3. O bloco sofre uma operação **XOR** com essa máscara.
4. A seed também é mascarada com a MGF e concatenada ao bloco codificado.
5. O bloco final recebe um **byte 0x00** no início para garantir a integridade.

🔹 **Diagrama do Processo**:  

![Diagrama OAEP](imgs/diagrama-oaep.png)

#### ⚠ Label Opcional no Projeto

Neste projeto, a **label** encontrada no padding do OAEP **não foi utilizada**, pois trata-se de uma medida de segurança adicional que não se mostrou necessária para o propósito da aplicação. O algoritmo foi implementado sem esse valor, mantendo a estrutura funcional do OAEP.

### Assinatura Digital

A assinatura digital de um arquivo garante **autenticidade** e **não repúdio**, permitindo que o emissor comprove a autoria da mensagem e que o receptor verifique sua integridade. 

Neste projeto, a assinatura digital é gerada utilizando **RSA** para criptografar o **hash da mensagem**. 

#### 🔐 Processo da Assinatura Digital

##### 📤 **No Emissor:**
1. Calcula-se o **hash** da mensagem utilizando SHA3-256.
2. O hash é **criptografado** com a **chave privada** (assinatura).
3. A mensagem original é **concatenada** com a assinatura criptografada e enviada ao receptor.

##### 📥 **No Receptor:**
1. A mensagem e a assinatura são **separadas**.
2. O receptor **calcula o hash** da mensagem recebida.
3. A assinatura é **descriptografada** usando a **chave pública** do emissor.
4. O hash gerado é **comparado** com o hash obtido na assinatura.  
   - ✅ **Se forem iguais**, a assinatura é válida.  
   - ❌ **Se forem diferentes**, a mensagem foi alterada ou a assinatura é inválida.

🔹 **Diagrama do Processo:**  

![Diagrama Assinatura Digital](imgs/diagrama-assinatura-digital.png)

## Implementação

O projeto foi dividido em três módulos principais e em dois módulos de integração:

#### Principais
- **RSA**
- **OAEP**
- **Signature**

#### Integração
- **Encode Decode**
- **Main**

#
### RSA
1. **Geração de Primos**

```py
def random_primes_lib():
    p = randprime(2**1023, 2**1024)  
    q = randprime(2**1023, 2**1024)
    return p, q

def random_primes() -> Tuple[int, int]:
    while True:
        primes = []
        num = secrets.randbits(1024) | 1 
        
        if miller_rabin(num, 40):
            primes.append(num)
            if len(primes) == 2:
                return primes[0], primes[1]    
```
- `random_primes_lib`: usa uma biblioteca para gerar dois primos rapidamente, visando testar a aplicação.

- `random_primes`: gera valores ímpares que passarão pela função miller_rabin para validar a primalidade, e então retorna dois primos.

```py
def miller_rabin(n: int, k: int) -> bool:

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
```

A função `miller_rabin` realiza um teste probabilístico para verificar se um número `n` é primo.

#### Parâmetros:
- **`n`**: Número a ser testado.
- **`k`**: Número de rodadas do teste.

#### Processo:

1. **Verificações Iniciais**: Retorna `False` para `n < 2` ou 
`n` par (exceto 2 e 3). Retorna `True` para `n` igual a 2 ou 3.

2. **Fatoração de `n - 1`**: Decompõe `n - 1` em `2^r * d` com `d` ímpar.

3. **Rodadas de Teste**:
   - Seleciona um número aleatório `a` no intervalo [2, `n` - 2].
   - Calcula `aux = a^d % n`.
   - Verifica se `aux` é 1 ou `n - 1`.
   - Repetidamente eleva `aux` ao quadrado e verifica se é `n - 1`.
   - Se nenhum dos resultados for `n - 1`, retorna `False`.

4. **Conclusão**: Se todas as rodadas passarem, retorna `True`.

Exemplo de Uso:
```python
result = miller_rabin(17, 5)
print(result)  # Saída: True
```
#
2. **Geração das Chaves**
```py
def key_gen(p: int, q: int) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537 
    if gcd(e, phi_n) != 1:
        while True:
            e = secrets.randbelow(phi_n - 2) + 2
            if gcd(e, phi_n) == 1:
                break

    d = mod_inverse(e, phi_n)
    return (n, e), (n, d)
```
A função `key_gen` gera um par de chaves RSA (chave pública e chave privada) com base em dois números primos `p` e `q`.

#### Parâmetros:
- **`p`**: Um número primo.
- **`q`**: Outro número primo.

#### Retorno:
- Retorna um par de tuplas. A primeira tupla representa a chave pública `(n, e)`, e a segunda tupla representa a chave privada `(n, d)`.

#### Descrição do Processo:
1. **Cálculo de `n` e `phi_n`**:
   - `n` é calculado como `p * q`.
   - `phi_n` é calculado como `(p - 1) * (q - 1)`.

2. **Escolha de `e`**:
   - Inicialmente, `e` é definido como `65537`, um valor comumente usado como expoente público.
   - Se `gcd(e, phi_n) != 1`, significa que `e` não é coprimo com `phi_n`, então um novo valor para `e` é escolhido aleatoriamente até que `gcd(e, phi_n) == 1`.

3. **Cálculo de `d`**:
   - `d` é calculado como o inverso modular de `e` mod `phi_n` usando a função.

4. **Retorno**:
   - A função retorna as chaves RSA: a chave pública `(n, e)` e a chave privada `(n, d)`.

#### Exemplo de Uso:
```py
public_key, private_key = key_gen(61, 53)
print(f"Chave Pública: {public_key}")  # Saída: Chave Pública: (3233, 65537)
print(f"Chave Privada: {private_key}")  # Saída: Chave Privada: (3233, 2753)
```
#
3. **Criptografia e Decriptografia**

```py
def rsa_encryption(message: int, key: Tuple[int, int]) -> int:
    n, k = key[0], key[1]
    return pow(message, k, n)

def rsa_decryption(encrypted_message: int, key: Tuple[int, int]) -> int:
    n, k = key[0], key[1]
    return pow(encrypted_message, k, n)
```
A função `rsa_encryption` Realiza a criptografia de uma mensagem usando uma chave RSA.

- **Parâmetros**:
  - `message`: A mensagem a ser criptografada (como um número inteiro).

  - `key`: A chave pública `(n, k)`.

- **Retorno**: A mensagem criptografada.

- **Processo**:
  1. Extrai `n` e `k` da chave.
  2. Aplica a função de exponenciação modular `pow(message, k, n)` para criptografar a mensagem.

A função `rsa_decryption` Realiza a descriptografia de uma mensagem criptografada usando uma chave RSA.

- **Parâmetros**:
  - `encrypted_message`: A mensagem criptografada (como um número inteiro).
  - `key`: A chave privada `(n, k)`.

- **Retorno**: A mensagem descriptografada.

- **Processo**:
  1. Extrai `n` e `k` da chave.
  2. Aplica a função de exponenciação modular `pow(encrypted_message, k, n)` para descriptografar a mensagem.

#### Exemplo de Uso:
```py
encrypted = rsa_encryption(42, (3233, 65537))
print(f"Encrypted: {encrypted}")  # Saída: 2557

decrypted = rsa_decryption(encrypted, (3233, 2753))
print(f"Decrypted: {decrypted}")  # Saída: 42
```
#
### OAEP
```py
def mask_generator(seed: bytes, key_length: int, hash = hashlib.sha3_256) -> bytes:
    mask = b""
    counter = 0
    while len(mask) < key_length:
        counter_bytes = counter.to_bytes(4, "big")
        mask += hash(seed + counter_bytes).digest()
        counter += 1

    return mask[:key_length]
```
A função `mask_generator` gera uma máscara de comprimento `key_length` a partir de uma semente (`seed`) usando a função de hash SHA-3 256.

#### Parâmetros:
- **`seed`** O valor inicial usado para gerar a máscara.
- **`key_length`**: O comprimento desejado da máscara.
- **`hash`**: A função de hash a ser utilizada (por padrão, SHA-3 256).

#### Retorno:
- A máscara gerada com o comprimento especificado.

#### Descrição do Processo:
1. **Inicialização**:
   - `mask` é inicializada como uma string de bytes vazia.
   - `counter` é inicializado como 0.

2. **Geração da Máscara**:
   - Enquanto o comprimento da `mask` for menor que `key_length`:
     - Converte `counter` em bytes de 4 bytes.
     - Gera um valor de hash usando `seed` concatenado com `counter_bytes`.
     - Adiciona o valor de hash gerado à `mask`.
     - Incrementa `counter`.

3. **Retorno**:
   - Retorna a `mask` truncada para `key_length`.

#### Exemplo de Uso:
```py
seed = b'some_seed'
key_length = 32
mask = mask_generator(seed, key_length)
print(f"Mask: {mask}")
```
#

```py
def oaep_encode(block_message: bytes, key_length: int, hash = hashlib.sha3_256) -> bytes:
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
```
A função `oaep_encode` aplica padding em um bloco de uma mensagem usando OAEP (Optimal Asymmetric Encryption Padding).

#### Parâmetros:
- **`block_message`**: A mensagem em blocos a ser codificada.
- **`key_length`**: Comprimento da chave RSA em bits.
- **`hash`**: Função de hash usada para o padding (padrão: `hashlib.sha3_256`).

#### Retorno:
- A mensagem preenchida com OAEP.

#### Exceções:
- **`ValueError`**: Se o bloco de mensagem for maior do que o OAEP pode aceitar.
- **`OverflowError`**: Se o comprimento do padding (`padding_len`) for muito grande para ser processado.

#### Descrição do Processo:
1. **Inicialização**:
   - Calcula o comprimento do hash (`hash_len`) e o comprimento do bloco (`block_len`).
   
2. **Cálculo do Padding**:
   - Calcula o comprimento do padding (`padding_len`).
   - Verifica se o `padding_len` é válido; caso contrário, levanta uma exceção.
   
3. **Aplicação do Padding**:
   - Preenche o bloco com zeros (`b"\x00"`) seguido de `b"\x01"` e o bloco da mensagem.
   - Gera uma semente aleatória (`seed`).

4. **Geração e Aplicação das Máscaras**:
   - Gera a máscara do bloco (`block_mask`) e aplica ao bloco preenchido.
   - Gera a máscara da semente (`seed_mask`) e aplica à semente.

5. **Retorno**:
   - Retorna a mensagem codificada com OAEP, composta por `b'\x00'`, `masked_seed` e `masked_block`.

#### Exemplo de Uso:
```py
message = b"example message"
key_length = 2048
encoded_message = oaep_encode(message, key_length)
print(f"Encoded Message: {encoded_message}")
```
#

```py
def oaep_decode(encoded_message: bytes, key_length: int, hash = hashlib.sha3_256) -> bytes:
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
```
A função `oaep_decode` decodifica uma mensagem preenchida com OAEP (Optimal Asymmetric Encryption Padding).

#### Parâmetros:
- **`encoded_message`** (bytes): A mensagem codificada com OAEP.
- **`key_length`** (int): Comprimento da chave RSA em bits.
- **`hash`**: Função de hash usada para o padding (padrão: `hashlib.sha3_256`).

#### Retorno:
- A mensagem decodificada.

#### Exceções:
- **`ValueError`**: Se a mensagem codificada não contiver o delimitador `0x01`.

#### Descrição do Processo:
1. **Inicialização**:
   - Calcula o comprimento do hash (`hash_len`) e o comprimento do bloco (`block_len`).

2. **Separação das Máscaras**:
   - Divide `encoded_message` em `masked_seed` e `masked_block`.

3. **Geração e Aplicação das Máscaras**:
   - Gera a máscara da semente (`seed_mask`) e aplica à `masked_seed` para obter a semente (`seed`).
   - Gera a máscara do bloco (`block_mask`) e aplica à `masked_block` para obter o bloco preenchido (`padded_block`).

4. **Remoção do Padding**:
   - Procura o delimitador `0x01` em `padded_block`.
   - Levanta uma exceção se o delimitador não for encontrado.
   - Retorna a mensagem decodificada após o delimitador.

#### Exemplo de Uso:
```py
encoded_message = oaep_encode(b"example message", 2048)
decoded_message = oaep_decode(encoded_message, 2048)
print(f"Decoded Message: {decoded_message}") # Saída: Decoded Message: b'example message'
```
#
### Signature
```py
def sign_message(message: bytes, rsa_encryption: Callable[[int, Tuple[int, int]], int], private_key: Tuple[int, int], hash = hashlib.sha3_256
) -> bytes:
    print(f"🔹 Assinando mensagem: {message}") 

    message_hash = int.from_bytes(hash(message).digest(), byteorder="big")
    global_vars["Assinatura antes do RSA"] = message_hash

    print(f"🔹 Assinatura da mensagem antes do RSA: {message_hash}")  
    

    signature = rsa_encryption(message_hash, private_key)
    signed_bytes = signature.to_bytes((private_key[0].bit_length() + 7) // 8, byteorder="big")

    global_vars["Assinatura depois do RSA"] = int.from_bytes(signed_bytes)
    print(f"🔹 Assinatura gerada pós RSA: {int.from_bytes(signed_bytes)}")  

    return signed_bytes
```
A função `sign_message` assina uma mensagem calculando seu hash e criptografando-o com a chave privada RSA.

#### Parâmetros:
- **`message`**: A mensagem a ser assinada.
- **`rsa_encryption`**: Função RSA para criptografar o hash da mensagem.
- **`private_key`**: A chave privada `(n, d)`.
- **`hash`**: Função de hash usada para calcular o hash da mensagem (padrão: `hashlib.sha3_256`).

#### Retorno:
- A assinatura da mensagem.

#### Descrição do Processo:
1. **Cálculo do Hash**:
   - Calcula o hash da mensagem usando a função de hash especificada.
   - Converte o hash em um número inteiro.

2. **Criptografia do Hash**:
   - Criptografa o hash usando a função `rsa_encryption` e a chave privada.

3. **Conversão para Bytes**:
   - Converte a assinatura criptografada de volta para bytes.

4. **Depuração**:
   - Imprime mensagens de depuração para mostrar o processo de assinatura antes e depois da criptografia RSA.

#### Exemplo de Uso:
```py
message = b"example message"
private_key = (3233, 2753)  # Exemplo de chave privada
signature = sign_message(message, rsa_encryption, private_key)
print(f"Signature: {signature}")
```
#
```py
def verify_signature(message: bytes, signature: bytes, rsa_decryption: Callable[[int, Tuple[int, int]], int], public_key: Tuple[int, int], hash: Callable = hashlib.sha3_256
) -> bool:
    message_hash = int.from_bytes(hash(message).digest(), byteorder="big")
    print(f"🔹 Assinatura da mensagem original antes do RSA: {message_hash}")  

    decrypted_hash = rsa_decryption(int.from_bytes(signature), public_key)
    print(f"🔹 Hash descriptografado da assinatura: {decrypted_hash}")
    
    return message_hash == decrypted_hash
```

A função `verify_signature` verifica a assinatura de uma mensagem comparando o hash da mensagem com o hash descriptografado da assinatura.

#### Parâmetros:
- **`message`**: A mensagem cuja assinatura deve ser verificada.
- **`signature`**: A assinatura a ser verificada.
- **`rsa_decryption`**: Função RSA para descriptografar a assinatura.
- **`public_key`**: A chave pública `(n, e)`.
- **`hash`**: Função de hash usada para calcular o hash da mensagem (padrão: `hashlib.sha3_256`).

#### Retorno:
- Retorna `True` se a assinatura for válida e `False` caso contrário.

#### Descrição do Processo:
1. **Cálculo do Hash da Mensagem**:
   - Calcula o hash da mensagem usando a função de hash especificada.
   - Converte o hash em um número inteiro.

2. **Descriptografia da Assinatura**:
   - Descriptografa a assinatura usando a função `rsa_decryption` e a chave pública.

3. **Comparação dos Hashes**:
   - Compara o hash da mensagem com o hash descriptografado da assinatura.
   - Retorna `True` se os hashes forem iguais, indicando que a assinatura é válida; caso contrário, retorna `False`.

#### Exemplo de Uso:
```py
message = b"example message"
signature = sign_message(message, rsa_encryption, (3233, 2753))
public_key = (3233, 65537)  # Exemplo de chave pública
is_valid = verify_signature(message, signature, rsa_decryption, public_key)
print(f"Signature valid: {is_valid}")
```
#
### Encode Decode
```py
def encode_message(message: bytes, private_key: Tuple[int, int]) -> bytes:
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
        aux = oaep.oaep_encode(block, private_key[0].bit_length())
        padded_blocks.append(aux)

    return b"".join(padded_blocks) + b"|" + sign
```
A função `encode_message` cria uma assinatura, divide a mensagem e aplica OAEP (Optimal Asymmetric Encryption Padding) aos blocos.

#### Parâmetros:
- **`message`**: A mensagem a ser codificada.
- **`private_key`**: A chave privada RSA `(n, d)` usada para assinar e criptografar.

#### Retorno:
- A mensagem codificada e assinada.

#### Descrição do Processo:
1. **Divisão da Mensagem**:
   - Divide a mensagem em blocos de tamanho `max_block_bytes` (190 bytes).

2. **Criação da Assinatura**:
   - Gera uma assinatura da mensagem utilizando a função `sign_message` e a chave privada.

3. **Aplicação do Padding OAEP**:
   - Aplica OAEP a cada bloco da mensagem utilizando a função `oaep_encode`.

4. **Combinação dos Blocos**:
   - Junta os blocos codificados e a assinatura, separando-os com o delimitador `|`.

#### Exemplo de Uso:
```py
message = b"example message"
private_key = (3233, 2753)  # Exemplo de chave privada
encoded_message = encode_message(message, private_key)
print(f"Encoded Message: {encoded_message}")
```
#
```py
def decode_message(signed_message: bytes, public_key: Tuple[int, int]) -> Tuple[str, bool]:
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

    print(f"🔹 Mensagem extraída: {mensagem}") 
    print(f"🔹 Assinatura extraída: {int.from_bytes(sign)}") 
    booleano = signature.verify_signature(mensagem, sign, rsa.rsa_decryption, public_key)

    return mensagem.decode(), booleano
```
### Função `decode_message`

A função `decode_message` decodifica uma mensagem codificada, remove OAEP e verifica a assinatura.

#### Parâmetros:
- **`signed_message`**: A mensagem codificada e assinada.
- **`public_key`**: A chave pública RSA `(n, e)` usada para verificar a assinatura.

#### Retorno:
- A mensagem decodificada e um booleano indicando a validade da assinatura.

#### Descrição do Processo:
1. **Inicialização**:
   - Calcula o comprimento do bloco (`block_len`).

2. **Separação da Mensagem e Assinatura**:
   - Separa a mensagem codificada da assinatura usando `rsplit`.

3. **Decodificação dos Blocos**:
   - Divide a mensagem codificada em blocos de tamanho `block_len`.
   - Aplica OAEP a cada bloco usando `oaep_decode`.

4. **Combinação dos Blocos Decodificados**:
   - Junta os blocos decodificados para formar a mensagem original.

5. **Verificação da Assinatura**:
   - Verifica a validade da assinatura usando `verify_signature`.

#### Exemplo de Uso:
```py
signed_message = encode_message(b"example message", private_key)
decoded_message, is_valid = decode_message(signed_message, public_key)
print(f"Decoded Message: {decoded_message}")
print(f"Signature valid: {is_valid}")
```
# 
### Main
```py
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
```
A função `main` realiza a leitura de uma mensagem de um arquivo, gera chaves RSA, assina a mensagem, codifica-a usando OAEP, e verifica a assinatura.

#### Descrição do Processo:

1. **Leitura da Mensagem**:
    - Lê a mensagem do arquivo `mensagens/mensagem.txt`.
    - Exibe a mensagem lida.

2. **Geração de Chaves RSA**:
    - Gera dois números primos `p` e `q`.
    - Gera a chave pública e a chave privada RSA.

3. **Assinatura e Codificação da Mensagem**:
    - Assina a mensagem e a codifica usando OAEP.
    - Salva a mensagem assinada e codificada no arquivo `mensagens/mensagem_assinada.txt`.

4. **Leitura e Decodificação da Mensagem**:
    - Lê a mensagem assinada e codificada do arquivo.
    - Decodifica a mensagem e verifica a assinatura.

5. **Exibição dos Resultados**:
    - Exibe a mensagem decodificada e o resultado da verificação da assinatura.

#### Exemplo de Uso:
```py
main()
```

## Conclusão

A implementação do **RSA com OAEP** adiciona uma camada extra de segurança ao sistema, tornando a criptografia mais resistente a **ataques determinísticos** e garantindo maior **confidencialidade** dos dados transmitidos. O OAEP evita padrões previsíveis na criptografia RSA, fortalecendo sua segurança contra tentativas de intrusão.

Além disso, a **assinatura digital** assegura a **autenticidade e integridade** das mensagens, permitindo verificar sua origem e garantir que não sofreram alterações durante a transmissão. Esse recurso é essencial em cenários críticos, como **comunicações financeiras, governamentais e empresariais**, onde a confiabilidade da informação é fundamental.

A implementação deste projeto foi uma experiência enriquecedora, pois proporcionou uma compreensão mais profunda dos conceitos de **criptografia assimétrica, padding seguro e assinaturas digitais**. Além de reforçar o conhecimento teórico sobre **RSA e OAEP**, a prática ajudou a desenvolver habilidades essenciais, como **otimização de código, manipulação de grandes números e depuração de erros criptográficos**. No geral, o projeto não apenas consolidou o aprendizado, mas também despertou um maior interesse pela área de **segurança da informação**, demonstrando como algoritmos matemáticos se traduzem em soluções práticas para proteção de dados.