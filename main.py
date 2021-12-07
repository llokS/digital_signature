from Crypto.PublicKey import DSA
from Crypto.PublicKey import ECC
from Crypto.PublicKey import RSA

from Crypto.Signature import DSS
from Crypto.Signature import pkcs1_15

from Crypto.Hash import SHA256
from Crypto.Hash import SHA512


def GenKey(mode):
    if mode == 'DSA':
        key = DSA.generate(2048)

        f = open("public_DSA.bin", "wb")
        f.write(key.publickey().export_key('DER'))
        f.close()

        f = open("private_DSA.bin", "wb")
        f.write(key.export_key('DER'))
        f.close()
    elif mode == 'RSA-256':
        key = RSA.generate(2048)

        f = open("public_RSA-256.bin", "wb")
        f.write(key.publickey().export_key('DER'))
        f.close()

        f = open("private_RSA-256.bin", "wb")
        f.write(key.export_key('DER'))
        f.close()
    elif mode == 'RSA-512':
        key = RSA.generate(2048)

        f = open("public_RSA-512.bin", "wb")
        f.write(key.publickey().export_key('DER'))
        f.close()

        f = open("private_RSA-512.bin", "wb")
        f.write(key.export_key('DER'))
        f.close()
    elif mode == 'ECDSA':
        key = ECC.generate(curve='P-256')

        f = open("public_ECDSA.bin", "wb")
        f.write(key.public_key().export_key(format='DER'))
        f.close()

        f = open("private_ECDSA.bin", "wb")
        f.write(key.export_key(format='DER'))
        f.close()
    else:
        return Algorithm()


def SignFile(mode, name, key_name):
    with open(name, 'rb') as file:
        text = file.read()

    key_file = open(key_name, "rb")

    if mode == 'DSA':
        key = DSA.import_key(key_file.read())
        hash_obj = SHA256.new(text)

        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(hash_obj)

        f = open("sig_" + name + "_" + mode + "_.bin", "wb")
        f.write(signature)
        f.close()

    elif mode == 'RSA-256':
        key = RSA.import_key(key_file.read())
        hash_obj = SHA256.new(text)
        signature = pkcs1_15.new(key).sign(hash_obj)

        f = open("sig_" + name + "_" + mode + "_.bin", "wb")
        f.write(signature)
        f.close()

    elif mode == 'RSA-512':
        key = RSA.import_key(key_file.read())
        hash_obj = SHA512.new(text)
        signature = pkcs1_15.new(key).sign(hash_obj)

        f = open("sig_" + name + "_" + mode + "_.bin", "wb")
        f.write(signature)
        f.close()

    elif mode == 'ECDSA':
        key = ECC.import_key(key_file.read())
        hash_obj = SHA256.new(text)
        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(hash_obj)

        f = open("sig_" + name + "_" + mode + "_.bin", "wb")
        f.write(signature)
        f.close()

    file.close()
    key_file.close()


def SignIsTrue(mode, name, key_name, signature_name):
    with open(name, 'rb') as file:
        text = file.read()

    key_file = open(key_name, "rb")

    with open(signature_name, "rb") as sign:
        signature = sign.read()

    if mode == 'DSA':
        key = DSA.import_key(key_file.read())
        hash_obj = SHA256.new(text)
        verifier = DSS.new(key, 'fips-186-3')
        try:
            verifier.verify(hash_obj, signature)
            print("Сообщение подлинное")
        except ValueError:
            print("Сообщение не является подлинным")

    elif mode == 'RSA-256':
        key = RSA.import_key(key_file.read())
        hash_obj = SHA256.new(text)
        try:
            pkcs1_15.new(key).verify(hash_obj, signature)
            print("Подпись действительна")
        except (ValueError, TypeError):
            print("Подпись недействительна")
    elif mode == 'RSA-512':
        key = RSA.import_key(key_file.read())
        hash_obj = SHA512.new(text)
        try:
            pkcs1_15.new(key).verify(hash_obj, signature)
            print("Подпись действительна")
        except (ValueError, TypeError):
            print("Подпись недействительна")
    elif mode == 'ECDSA':
        key = ECC.import_key(key_file.read())
        hash_obj = SHA256.new(text)
        verifier = DSS.new(key, 'fips-186-3')
        try:
            verifier.verify(hash_obj, signature)
            print("Сообщение подлинное")
        except ValueError:
            print("Сообщение не является подлинным")

    file.close()
    key_file.close()
    sign.close()


def Go(mode):
    print('Выбранный алгоритм: ', mode)
    print("\t1. Генерация ключа подписи и ключа для проверки подписи\n\t2. Подпись файла\n\t3. Проверка подписи")
    flag = input()
    if flag == '0':
        return 0
    elif flag == '1':
        GenKey(mode)
    elif flag == '2':
        name = '2mb.txt'
        key = 'private_' + mode + '.bin'
        SignFile(mode, name, key)

    elif flag == '3':
        name = '2mb.txt'
        key = 'public_' + mode + '.bin'
        sign = "sig_" + name + "_" + mode + "_.bin"
        SignIsTrue(mode, name, key, sign)
    else:
        print('Go: Выберите действие')
        return Go


def Algorithm():
    print('Выбор алгоритма')
    print('\t1.RSA-256\n\t2.RSA-512\n\t3.DSA\n\t4.ECDSA')
    mode = input()
    if mode == '0':
        return 0
    elif mode == '1':
        alg = 'RSA-256'
    elif mode == '2':
        alg = 'RSA-512'
    elif mode == '3':
        alg = 'DSA'
    elif mode == '4':
        alg = 'ECDSA'
    else:
        print('Алгоритм не выбран')
        Algorithm()
    return alg


while (1):
    mode = Algorithm()
    if mode == 0:
        break
    Go(mode)