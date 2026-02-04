import hashlib
import math
import secrets
import statistics
import time


def string_to_bits(text: str) -> list[int]:
    """Converte uma string para uma lista de bits (0s e 1s)."""
    bits = []
    for character in text:
        binary_value = bin(ord(character))[2:].zfill(8)
        bits.extend([int(bit) for bit in binary_value])
    return bits


def bits_to_string(bits: list[int]) -> str:
    """Converte uma lista de bits de volta para texto."""
    characters = []
    for index in range(0, len(bits), 8):
        byte_chunk = bits[index : index + 8]
        if len(byte_chunk) < 8:
            break
        character_code = int("".join(map(str, byte_chunk)), 2)
        characters.append(chr(character_code))
    return "".join(characters)


def generate_entropy_seed(num_bits: int = 128) -> list[int]:
    """
    Gera uma seed de entropia criptograficamente segura.
    Utiliza o gerador de números aleatórios do sistema operacional.
    """
    num_bytes = (num_bits + 7) // 8
    random_bytes = secrets.token_bytes(num_bytes)

    hash_object = hashlib.sha256(random_bytes)
    hash_hex = hash_object.hexdigest()

    hash_integer = int(hash_hex, 16)
    binary_value = bin(hash_integer)[2:].zfill(256)

    return [int(bit) for bit in binary_value[:num_bits]]


def GEN(seed: list[int]) -> list[int]:
    """
    Gera uma chave criptográfica usando um Linear Congruential Generator (LCG).
    A chave terá 4 vezes o tamanho da seed de entrada.
    """
    key = []

    seed_string = "".join(map(str, seed))
    seed_bytes = seed_string.encode()
    seed_hash = hashlib.sha256(seed_bytes).digest()

    state = int.from_bytes(seed_hash[:4], byteorder="big")

    lcg_multiplier = 1664525
    lcg_increment = 1013904223
    lcg_modulus = 2**32

    target_size = len(seed) * 4

    for _ in range(target_size):
        state = (lcg_multiplier * state + lcg_increment) % lcg_modulus
        bit = (state >> 7) & 1
        key.append(bit)

    return key


def expand_key(key: list[int], required_size: int) -> list[int]:
    """
    Expande a chave até atingir o tamanho necessário para cifrar a mensagem.
    Utiliza o próprio gerador de chaves recursivamente.
    """
    if len(key) >= required_size:
        return key[:required_size]

    expanded_key = key.copy()

    while len(expanded_key) < required_size:
        seed_size = min(32, len(expanded_key))
        new_seed = expanded_key[-seed_size:]
        new_bits = GEN(new_seed)
        expanded_key.extend(new_bits)

    return expanded_key[:required_size]


def ENC(key: list[int], message: list[int]) -> list[int]:
    """
    Cifra uma mensagem usando um esquema de múltiplas rodadas com permutação.
    Implementa 3 rodadas de XOR com feedback e permutação para garantir difusão completa.
    """
    if len(key) < len(message) * 3:
        key = expand_key(key, len(message) * 3)

    ciphertext = message.copy()
    size = len(ciphertext)

    for round_number in range(3):
        round_key = key[round_number * size : (round_number + 1) * size]

        initialization_vector = _generate_initialization_vector(round_key, round_number)

        ciphertext = _apply_xor_with_feedback(
            ciphertext, round_key, initialization_vector
        )

        if round_number < 2:
            ciphertext = _permute_bits(ciphertext, round_key, round_number)

    return ciphertext


def DEC(key: list[int], ciphertext: list[int]) -> list[int]:
    """
    Decifra uma mensagem revertendo as operações de cifragem.
    Processa as rodadas em ordem inversa.
    """
    if len(key) < len(ciphertext) * 3:
        key = expand_key(key, len(ciphertext) * 3)

    message = ciphertext.copy()
    size = len(message)

    for round_number in range(2, -1, -1):
        if round_number < 2:
            round_key = key[round_number * size : (round_number + 1) * size]
            message = _reverse_permute_bits(message, round_key, round_number)

        round_key = key[round_number * size : (round_number + 1) * size]
        initialization_vector = _generate_initialization_vector(round_key, round_number)
        message = _reverse_xor_with_feedback(message, round_key, initialization_vector)

    return message


def _generate_initialization_vector(
    round_key: list[int], round_number: int
) -> list[int]:
    """Gera um vetor de inicialização único para cada rodada baseado na chave."""
    iv_seed = str(round_number) + "".join(
        map(str, round_key[: min(16, len(round_key))])
    )
    iv_hash = hashlib.sha256(iv_seed.encode()).digest()
    return [int(bit) for bit in bin(iv_hash[0])[2:].zfill(8)]


def _apply_xor_with_feedback(
    data: list[int], round_key: list[int], initialization_vector: list[int]
) -> list[int]:
    """Aplica XOR com feedback usando um buffer circular de 8 bits."""
    history = initialization_vector.copy()
    result = []

    for index in range(len(data)):
        feedback = 0
        for history_bit in history:
            feedback ^= history_bit

        cipher_bit = data[index] ^ round_key[index] ^ feedback
        result.append(cipher_bit)
        history = history[1:] + [cipher_bit]

    return result


def _reverse_xor_with_feedback(
    data: list[int], round_key: list[int], initialization_vector: list[int]
) -> list[int]:
    """Reverte a operação de XOR com feedback."""
    history = initialization_vector.copy()
    result = []

    for index in range(len(data)):
        feedback = 0
        for history_bit in history:
            feedback ^= history_bit

        message_bit = data[index] ^ round_key[index] ^ feedback
        result.append(message_bit)
        history = history[1:] + [data[index]]

    return result


def _permute_bits(
    data: list[int], round_key: list[int], round_number: int
) -> list[int]:
    """
    Permuta os bits usando uma função linear dependente da chave.
    Garante que a permutação varie com diferentes chaves.
    """
    size = len(data)
    permuted = [0] * size

    permutation_seed = str(round_number) + "".join(
        map(str, round_key[: min(32, len(round_key))])
    )
    permutation_hash = hashlib.sha256(permutation_seed.encode()).digest()

    multiplier = int.from_bytes(permutation_hash[0:2], "big") % size
    offset = int.from_bytes(permutation_hash[2:4], "big") % size

    while multiplier == 0 or math.gcd(multiplier, size) != 1:
        multiplier = (multiplier + 1) % size
        if multiplier == 0:
            multiplier = 1

    for index in range(size):
        new_position = (multiplier * index + offset) % size
        permuted[new_position] = data[index]

    return permuted


def _reverse_permute_bits(
    data: list[int], round_key: list[int], round_number: int
) -> list[int]:
    """Reverte a permutação de bits."""
    size = len(data)
    unpermuted = [0] * size

    permutation_seed = str(round_number) + "".join(
        map(str, round_key[: min(32, len(round_key))])
    )
    permutation_hash = hashlib.sha256(permutation_seed.encode()).digest()

    multiplier = int.from_bytes(permutation_hash[0:2], "big") % size
    offset = int.from_bytes(permutation_hash[2:4], "big") % size

    while multiplier == 0 or math.gcd(multiplier, size) != 1:
        multiplier = (multiplier + 1) % size
        if multiplier == 0:
            multiplier = 1

    for index in range(size):
        new_position = (multiplier * index + offset) % size
        unpermuted[index] = data[new_position]

    return unpermuted


if __name__ == "__main__":
    start_time = time.perf_counter()

    print("=== Sistema Criptográfico ===\n")

    seed = generate_entropy_seed(num_bits=64)
    key = GEN(seed)
    print(f"Seed: {len(seed)} bits | Chave: {len(key)} bits")

    original_text = "Esta mensagem testa expansao!"
    message_bits = string_to_bits(original_text)

    ciphertext = ENC(key, message_bits)
    decrypted_bits = DEC(key, ciphertext)
    decrypted_text = bits_to_string(decrypted_bits)

    print(f"Mensagem: '{original_text}'")
    print(f"Decifrada: '{decrypted_text}'")
    print(f"Status: {'Sucesso' if message_bits == decrypted_bits else 'Erro'}\n")

    print("=== Teste de Difusão ===")

    diffusion_percentages = []
    for position in range(len(message_bits)):
        modified_message = message_bits.copy()
        modified_message[position] = 1 - modified_message[position]
        modified_ciphertext = ENC(key, modified_message)
        differences = sum(
            1 for i in range(len(ciphertext)) if ciphertext[i] != modified_ciphertext[i]
        )
        percentage = (differences / len(ciphertext)) * 100
        diffusion_percentages.append(percentage)

    mean = statistics.mean(diffusion_percentages)
    average_differences = int(mean * len(ciphertext) / 100)

    print(
        f"Mudança na mensagem: {average_differences}/{len(ciphertext)} bits alterados na cifra ({mean:.1f}%)\n"
    )

    print("=== Teste de Confusão ===")
    modified_seed = seed.copy()
    modified_seed[0] = 1 - modified_seed[0]
    modified_key = GEN(modified_seed)
    confusion_ciphertext = ENC(modified_key, message_bits)
    confusion_differences = sum(
        1 for i in range(len(ciphertext)) if ciphertext[i] != confusion_ciphertext[i]
    )
    confusion_percentage = (confusion_differences / len(ciphertext)) * 100

    print(
        f"Mudança na seed: {confusion_differences}/{len(ciphertext)} bits alterados na cifra ({confusion_percentage:.1f}%)"
    )

    end_time = time.perf_counter()
    execution_time = end_time - start_time
    print(f"\nTempo de execução: {execution_time:.4f} segundos")
