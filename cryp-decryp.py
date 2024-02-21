import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_text(password, plaintext):
    # Преобразование пароля в байтовую строку
    password = password.encode()

    # Генерация случайной соли
    salt = os.urandom(16)

    # Генерация ключа на основе пароля
    key = generate_key(password, salt)

    # Настройка алгоритма шифрования
    cipher = Cipher(algorithms.AES(key), modes.CBC(salt), backend=default_backend())
    encryptor = cipher.encryptor()

    # Добавление дополнения для длины блока
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()

    # Шифрование данных
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return salt + ciphertext

def decrypt_text(password, ciphertext):
    # Преобразование пароля в байтовую строку
    password = password.encode()

    # Извлечение соли из шифротекста
    salt = ciphertext[:16]
    ciphertext = ciphertext[16:]

    # Генерация ключа на основе пароля и соли
    key = generate_key(password, salt)

    # Попытка создать объект шифра
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(salt), backend=default_backend())
    except TypeError:
        return "Ошибка: неправильный пароль"

    # Настройка алгоритма дешифрования
    decryptor = cipher.decryptor()

    # Расшифровка данных
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Удаление дополнения
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_plaintext = unpadder.update(plaintext) + unpadder.finalize()
    return unpadded_plaintext.decode()

def main():
    print("Что вы хотите сделать?")
    print("1. Зашифровать")
    print("2. Расшифровать")
    choice = input("Введите номер выбранного действия: ")

    if choice == "1":
        password = input("Введите пароль: ")
        plaintext = input("Введите текст для шифрования: ")
        encrypted_text = encrypt_text(password, plaintext)
        print("Зашифрованный текст:", base64.urlsafe_b64encode(encrypted_text).decode())
    elif choice == "2":
        password = input("Введите пароль: ")
        ciphertext = base64.urlsafe_b64decode(input("Введите зашифрованный текст: "))
        decrypted_text = decrypt_text(password, ciphertext)
        print("Расшифрованный текст:", decrypted_text)
    else:
        print("Неверный выбор")

if __name__ == "__main__":
    main()
