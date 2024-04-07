import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
sharedSecretKey = os.urandom(32)

messageData = {
    'Soldier' : [
        {'message': 'Oi senior! Why play WoW when you can PLAY WoW', 'time': '2024-04-07'},
        {'message': 'This is me working on a project I doubt I\'ll use. It\'s an encryption algorithm!', 'time': '2024-04-07'},
        {'message': 'It is supposed to really secure messages but we will find out for sure!', 'time': '2024-04-07'}
    ],
    'Kitti': [
        {'message': 'Because I do what I want!', 'time': '2024-04-07'},
        {'message': 'You may not use it but it is still really cool!', 'time': '2024-04-07'},
        {'message': 'Aight bet we will test it out!', 'time': '2024-04-07'}
    ]
}

def encryptMessage(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    paddedMessage = message + (16 - len(message) % 16) * chr(16 - len(message) % 16)
    ciphertext = encryptor.update(paddedMessage.encode()) + encryptor.finalize()
    return iv + ciphertext

def decryptMessage(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    paddingLength = plaintext[-1]
    plaintext = plaintext[:-paddingLength]
    return plaintext.decode()

for person, messages in messageData.items():
    for message in messages:
        encryptedMessage = encryptMessage(message["message"], sharedSecretKey)
        message['message'] = encryptedMessage.hex()

print('Encrypted messageData dictionary: ')
print(messageData)

for person, messages in messageData.items():
    for message in messages:
        ciphertext = bytes.fromhex(message['message'])
        decryptedMessage = decryptMessage(ciphertext, sharedSecretKey)
        message['message'] = decryptedMessage

print('Decrypted messageData dictionary: ')
print(messageData)