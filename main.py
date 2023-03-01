from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics.pairwise import cosine_similarity

english_freq = {'a': 0.0817, 'b': 0.0149, 'c': 0.0278, 'd': 0.0425, 'e': 0.1270,
                'f': 0.0223, 'g': 0.0202, 'h': 0.0609, 'i': 0.0697, 'j': 0.0015,
                'k': 0.0077, 'l': 0.0403, 'm': 0.0241, 'n': 0.0675, 'o': 0.0751,
                'p': 0.0193, 'q': 0.0010, 'r': 0.0599, 's': 0.0633, 't': 0.0906,
                'u': 0.0276, 'v': 0.0098, 'w': 0.0236, 'x': 0.0015, 'y': 0.0197,
                'z': 0.0007}

def caesar_decrypt(ciphertext, key):
    """
    Decrypt the ciphertext using the Caesar cipher with the given key.
    """
    plaintext = ""
    for c in ciphertext:
        if c.isalpha():
            plaintext += chr((ord(c) - key - ord('a')) % 26 + ord('a'))
        else:
            plaintext += c
    return plaintext

def vigenere_decrypt(ciphertext, key):
    """
    Decrypt the ciphertext using the Vigenere cipher with the given key.
    """
    plaintext = ""
    key_index = 0
    for c in ciphertext:
        if c.isalpha():
            key_char = key[key_index]
            key_index = (key_index + 1) % len(key)
            plaintext += chr((ord(c) - ord(key_char)) % 26 + ord('a'))
        else:
            plaintext += c
    return plaintext

def rail_fence_decrypt(ciphertext, key):
    """
    Decrypt the ciphertext using the rail fence cipher with the given key.
    """
    fence = [['\n' for i in range(len(ciphertext))] for j in range(key)]
    rail = 0
    for i in range(len(ciphertext)):
        fence[rail][i] = '.'
        rail += 1
        if rail == key:
            rail = 0
    index = 0
    for j in range(key):
        for i in range(len(ciphertext)):
            if fence[j][i] == '.' and index < len(ciphertext):
                fence[j][i] = ciphertext[index]
                index += 1
    plaintext = ''.join([c for c in fence[0]])    
    return plaintext.replace('\n', '')

def transposition_decrypt(ciphertext, key):
    """
    Decrypt the ciphertext using the transposition cipher with the given key.
    """
    num_columns = len(ciphertext) // key
    num_rows = key
    num_broken_columns = len(ciphertext) % key
    plaintext = ""
    col = 0
    row = 0
    for i in range(len(ciphertext)):
        if col < num_broken_columns and row == num_rows - 1:
            num_cols_for_this_row = num_columns + 1
        else:
            num_cols_for_this_row = num_columns
        plain_index = col * num_rows + row
        if plain_index < len(ciphertext):
            plaintext += ciphertext[plain_index]
        col += 1
        if col == num_cols_for_this_row:
            col = 0
            row += 1
    return plaintext

def detect_key(ciphertext, decrypt_func, key_length):
    """
    Detect the key for the given ciphertext using the given decryption function and key length.
    """
    blocks = []
    for i in range(key_length):
        blocks.append("")
    for i in range(len(ciphertext)):
        blocks[i % key_length] += ciphertext[i]
    key = ""
    for block in blocks:
        block_freq = get_frequency_distribution(block)
        best_score = float("inf")
        best_key = None
        for i in range(26):
            shifted_freq = {}
            for letter, freq in block_freq.items():
                shifted_letter = chr((ord(letter) - i) % 26 + ord('a'))
                shifted_freq[shifted_letter] = freq
            score = get_similarity_score(shifted_freq, english_freq)
            if score < best_score:
                best_score = score
                best_key = i
        key += chr(best_key + ord('a'))
    return key

def get_frequency_distribution(text):
    """
    Get the frequency distribution of the letters in the given text.
    """
    freq = {}
    for c in text:
        if c.isalpha():
            c = c.lower()
            freq[c] = freq.get(c, 0) + 1
    total = sum(freq.values())
    for c in freq:
        freq[c] /= total
    return freq

def get_similarity_score(sentence1, sentence2):
    """
    Calculate the similarity score between two sentences using cosine similarity.

    Args:
    sentence1 (str): The first sentence.
    sentence2 (str): The second sentence.

    Returns:
    float: The cosine similarity score between the two sentences.
    """
    # Create a CountVectorizer object
    vectorizer = CountVectorizer()

    # Generate the count matrix
    count_matrix = vectorizer.fit_transform([sentence1, sentence2])

    # Get the cosine similarity score
    cosine_score = cosine_similarity(count_matrix)[0][1]

    return cosine_score

def detect_encryption_method(ciphertext):
    """
    Detect the encryption method and key for the given ciphertext.
    """
    methods = [caesar_decrypt, vigenere_decrypt, rail_fence_decrypt, transposition_decrypt]
    best_score = float("inf")
    best_method = None
    best_key = None
    for method in methods:
        for key_length in range(1, len(ciphertext)):
            try:
                key = detect_key(ciphertext, method, key_length)
                plaintext = method(ciphertext, key)
                freq = get_frequency_distribution(plaintext)
                score = get_similarity_score(freq, english_freq)
                if score < best_score:
                    best_score = score
                    best_method = method
                    best_key = key
            except:
                pass
    return best_method, best_key

def decrypt(ciphertext):
    """
    Decrypt the ciphertext using the most likely encryption method and key.
    """
    method, key = detect_encryption_method(ciphertext)
    plaintext = method(ciphertext, key)
    print("Encryption Method: {}".format(method.__name__))
    print("Key: {}".format(key))
    print("Decrypted: {}".format(plaintext))

def main():
  ciphertext = input("Enter the encrypted string: ")
  decrypt(ciphertext)  

  

main()
