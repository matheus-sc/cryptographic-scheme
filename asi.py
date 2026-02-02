import os
import time

VIDEO_PATH = "./lava-lamp.mp4"


def str_to_bits(s: str) -> list[int]:
    """Converte uma string para uma lista de bits (0s e 1s)."""
    bits = []
    for char in s:
        # Pega o valor ASCII, converte p/ binário, remove '0b', preenche com 0 à esq (8 bits)
        bin_val = bin(ord(char))[2:].zfill(8)
        bits.extend([int(b) for b in bin_val])
    return bits


def bits_to_str(bits: list[int]) -> str:
    """Converte uma lista de bits de volta para texto."""
    chars = []
    for i in range(0, len(bits), 8):
        byte_chunk = bits[i : i + 8]
        # Se sobrar pedaço menor que 8 bits, ignora
        if len(byte_chunk) < 8:
            break
        char_code = int("".join(map(str, byte_chunk)), 2)
        chars.append(chr(char_code))
    return "".join(chars)


def get_video_entropy_bits(video_path: str, num_bits: int = 128) -> list[int]:
    """
    Extrai entropia de um vídeo (ex: lâmpadas de lava).
    Inspirado no sistema da Cloudflare.
    """
    import hashlib

    import cv2

    # Abre o vídeo
    cap = cv2.VideoCapture(video_path)
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

    if total_frames == 0:
        cap.release()
        raise Exception("Vídeo não encontrado ou inválido")

    # Escolhe frame aleatório (baseado em tempo)
    frame_aleatorio = int(time.time_ns()) % total_frames
    cap.set(cv2.CAP_PROP_POS_FRAMES, frame_aleatorio)

    ret, frame = cap.read()
    if not ret:
        cap.release()
        raise Exception("Erro ao ler vídeo")

    # Extrai valores RGB de pixels aleatórios
    altura, largura, _ = frame.shape
    pixels_entropia = []

    for _ in range(100):  # 100 pixels aleatórios
        x = (int(time.time_ns()) ^ os.getpid()) % largura
        y = (int(time.time_ns()) ^ id(object())) % altura
        pixel = frame[y, x]  # [B, G, R]
        pixels_entropia.extend(pixel)

    # Hash SHA-256 para garantir distribuição uniforme
    dados_brutos = bytes(pixels_entropia)
    hash_obj = hashlib.sha256(dados_brutos)
    hash_hex = hash_obj.hexdigest()

    # Converte para bits
    hash_int = int(hash_hex, 16)
    bin_val = bin(hash_int)[2:].zfill(256)

    cap.release()
    return [int(b) for b in bin_val[:num_bits]]


def GEN(seed: list[int]) -> list[int]:
    import hashlib

    K = []

    # Converte seed para bytes e faz hash para evitar colisões
    seed_str = "".join(map(str, seed))
    seed_bytes = seed_str.encode()
    hash_seed = hashlib.sha256(seed_bytes).digest()

    # Usa os primeiros 4 bytes do hash como estado inicial
    estado = int.from_bytes(hash_seed[:4], byteorder="big")

    # Parâmetros para garantir boa "Confusão" (números primos grandes)
    a = 1664525
    c = 1013904223
    m = 2**32

    # O tamanho alvo é 4 vezes o tamanho da seed
    tamanho_alvo = len(seed) * 4

    # Gera bit a bit
    for _ in range(tamanho_alvo):
        # Fórmula: X_next = (a * X_curr + c) % m
        estado = (a * estado + c) % m

        # Pega um bit do resultado (bit 7 para variar mais)
        bit = (estado >> 7) & 1
        K.append(bit)

    return K


def expandir_chave(K: list[int], tamanho_necessario: int) -> list[int]:
    """
    Expande a chave K até ter o tamanho necessário.
    Permite cifrar mensagens de qualquer tamanho.
    """
    if len(K) >= tamanho_necessario:
        return K[:tamanho_necessario]

    K_expandida = K.copy()

    while len(K_expandida) < tamanho_necessario:
        # Usa os últimos bits da chave como seed para gerar mais
        # Pega pelo menos 32 bits para a seed, ou o que tiver disponível
        seed_size = min(32, len(K_expandida))
        nova_seed = K_expandida[-seed_size:]

        # Gera mais bits
        novos_bits = GEN(nova_seed)
        K_expandida.extend(novos_bits)

    return K_expandida[:tamanho_necessario]


def ENC(K: list[int], M: list[int]) -> list[int]:
    # Expande a chave automaticamente se a mensagem for maior
    if len(K) < len(M):
        K = expandir_chave(K, len(M))

    # Trunca K se for maior que M
    K = K[: len(M)]

    C = []
    ultimo_bit_cifra = 0  # Valor inicial (IV virtual)

    for i in range(len(M)):
        # C[i] = M[i] XOR K[i] XOR C[i-1]
        # Isso faz com que mudar 1 bit no começo mude tudo depois (Difusão)
        bit_cifra = M[i] ^ K[i] ^ ultimo_bit_cifra
        C.append(bit_cifra)
        ultimo_bit_cifra = bit_cifra

    return C


def DEC(K: list[int], C: list[int]) -> list[int]:
    # Expande a chave automaticamente se a cifra for maior
    if len(K) < len(C):
        K = expandir_chave(K, len(C))

    # Trunca K se for maior que C
    K = K[: len(C)]

    M = []
    ultimo_bit_cifra = 0

    for i in range(len(C)):
        # Reverte a lógica: M[i] = C[i] XOR K[i] XOR C[i-1]
        bit_msg = C[i] ^ K[i] ^ ultimo_bit_cifra
        M.append(bit_msg)
        ultimo_bit_cifra = C[i]  # Atualiza para o próximo passo

    return M


if __name__ == "__main__":
    print("--- Início do Trabalho ---")

    # 1. Gerar Seed (Baseada em entropia de vídeo - lâmpadas de lava)
    seed = get_video_entropy_bits(VIDEO_PATH, num_bits=64)
    print(f"Seed gerada ({len(seed)} bits): {seed}")

    # 2. Gerar Chave (GEN)
    # A chave base terá 4x o tamanho da seed (64 bits * 4 = 256 bits)
    inicio_gen = time.time()
    chave = GEN(seed)
    fim_gen = time.time()
    print(f"Chave gerada ({len(chave)} bits): {chave[:10]}... (truncado)")
    print(f"Tempo de execução GEN: {fim_gen - inicio_gen:.6f}s")

    # 3. Definir Mensagem
    # A mensagem pode ter qualquer tamanho - a chave será expandida automaticamente
    # Mensagem de 30 caracteres = 240 bits (chave de 256 bits será truncada para 240)
    texto_original = "Esta mensagem testa expansao!"
    msg_bits = str_to_bits(texto_original)

    print(f"\nMensagem Original: '{texto_original}'")
    print(f"Bits Mensagem ({len(msg_bits)} bits): {msg_bits}")

    # 4. Criptografar (ENC)
    cifra = ENC(chave, msg_bits)
    print(f"Cifra gerada: {cifra}")

    # 5. Descriptografar (DEC)
    msg_recuperada_bits = DEC(chave, cifra)
    texto_recuperado = bits_to_str(msg_recuperada_bits)
    print(f"Texto Recuperado: '{texto_recuperado}'")

    # Verificação
    if msg_bits == msg_recuperada_bits:
        print("\nSUCESSO: A mensagem descriptografada é igual à original.")
    else:
        print("\nERRO: A mensagem foi corrompida.")

    print("\n--- Teste Rápido de Difusão (Critério 3) ---")
    # Vamos mudar o primeiro bit da mensagem e ver quantos bits da cifra mudam
    msg_bits_mod = msg_bits.copy()
    msg_bits_mod[0] = 1 - msg_bits_mod[0]  # Inverte o primeiro bit

    cifra_mod = ENC(chave, msg_bits_mod)

    diferencas = sum([1 for i in range(len(cifra)) if cifra[i] != cifra_mod[i]])
    porcentagem = (diferencas / len(cifra)) * 100
    print(
        f"Ao mudar 1 bit na mensagem, {diferencas} bits mudaram na cifra ({porcentagem:.1f}%)."
    )
    print("Nota: Devido ao 'Feedback' no ENC, isso deve ser alto (aprox 50%).")

    print("\n--- Teste de Confusão (Critério 4) ---")
    # Vamos mudar o primeiro bit da seed e ver quantos bits da cifra mudam
    seed_mod = seed.copy()
    seed_mod[0] = 1 - seed_mod[0]  # Inverte o primeiro bit da seed

    # Gera nova chave com seed modificada
    chave_mod = GEN(seed_mod)

    # Cifra a MESMA mensagem com a chave modificada
    cifra_mod_conf = ENC(chave_mod, msg_bits)

    diferencas_conf = sum(
        [1 for i in range(len(cifra)) if cifra[i] != cifra_mod_conf[i]]
    )
    porcentagem_conf = (diferencas_conf / len(cifra)) * 100
    print(
        f"Ao mudar 1 bit na seed, {diferencas_conf} bits mudaram na cifra ({porcentagem_conf:.1f}%)."
    )
    print("Nota: Devido ao LCG no GEN, isso deve ser alto (aprox 50%).")
