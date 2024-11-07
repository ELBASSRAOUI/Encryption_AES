import os
import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Fonction pour convertir l'image en matrice et l'enregistrer dans un fichier texte
def image_to_matrix(image_path):
    image = Image.open(image_path)
    image = image.convert('RGB')  # Convertit l'image en RGB
    matrix = np.array(image)
    return matrix

# Fonction pour chiffrer la matrice avec AES
def encrypt_matrix(matrix, key):
    backend = default_backend()
    iv = os.urandom(16)  # Vecteur d'initialisation aléatoire
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()

    # Transformer la matrice en bytes et chiffrer
    matrix_bytes = matrix.tobytes()
    encrypted_data = encryptor.update(matrix_bytes) + encryptor.finalize()

    return encrypted_data, iv

# Fonction pour sauvegarder la matrice dans un fichier texte
def save_matrix_to_file(filename, matrix):
    np.savetxt(filename, matrix.reshape(-1, matrix.shape[2]), fmt='%d')

# Fonction pour sauvegarder les données chiffrées dans un fichier texte
def save_encrypted_data(filename, encrypted_data, iv):
    with open(filename, 'wb') as f:
        f.write(iv)  # Sauvegarde du vecteur d'initialisation
        f.write(encrypted_data)  # Sauvegarde des données chiffrées

# Fonction pour déchiffrer les données
def decrypt_data(encrypted_data, key, iv, size):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Transformer les bytes déchiffrés en matrice
    matrix = np.frombuffer(decrypted_data, dtype=np.uint8)
    matrix = matrix.reshape((size[1], size[0], 3))  # Reshape avec les dimensions de l'image

    return matrix

# Fonction pour sauvegarder l'image déchiffrée
def matrix_to_image(matrix, output_path):
    image = Image.fromarray(matrix)
    image.save(output_path)

# Fonction principale
def main():
    image_path = input("Entrez le chemin de l'image satellite : ").strip()
    output_dir = r"C:\Users\MTechno\Desktop\STAGE\resultat"
    os.makedirs(output_dir, exist_ok=True)  # Créer le répertoire s'il n'existe pas

    key = os.urandom(32)  # Clé AES de 256 bits

    # Étape 1 : Convertir l'image en matrice
    matrix = image_to_matrix(image_path)

    # Étape 2 : Enregistrer la matrice dans un fichier texte
    matrix_filename = os.path.join(output_dir, 'image_matrix.txt')
    save_matrix_to_file(matrix_filename, matrix)
    print(f"Matrice de l'image enregistrée dans : {matrix_filename}")

    # Étape 3 : Chiffrer la matrice
    encrypted_data, iv = encrypt_matrix(matrix, key)

    # Étape 4 : Afficher la clé de chiffrement
    print(f"Clé de chiffrement (AES) : {key.hex()}")

    # Étape 5 : Enregistrer les données chiffrées dans un fichier texte
    encrypted_filename = os.path.join(output_dir, 'image_encrypted.bin')
    save_encrypted_data(encrypted_filename, encrypted_data, iv)
    print(f"Image chiffrée enregistrée dans : {encrypted_filename}")

    # Simulation de déchiffrement
    with open(encrypted_filename, 'rb') as f:
        iv = f.read(16)  # Lire le vecteur d'initialisation
        encrypted_data = f.read()  # Lire les données chiffrées

    # Étape 6 : Déchiffrer les données
    decrypted_matrix = decrypt_data(encrypted_data, key, iv, matrix.shape)

    # Étape 7 : Sauvegarder l'image déchiffrée
    decrypted_image_path = os.path.join(output_dir, 'image_decrypted.png')
    matrix_to_image(decrypted_matrix, decrypted_image_path)
    print(f"L'image déchiffrée enregistrée sous : {decrypted_image_path}")

if __name__ == "__main__":
    main()
    input("Appuyez sur Entrée pour fermer...") 

