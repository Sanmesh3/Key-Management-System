"""
SJSU ID: 014370759
Name: Sanmesh Suhas Bhosale
This is an implementation of a Key Management System.
"""
# Sample Private Key: E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262
# Sample DES3 Key: This is sample DES3 key.
# Sample Blowfish Key: This is fifty-six byte Blowfish key used for encryption.
# Sample RC2 Key: A very long and confidential key for implementing the RC2 cipher

from Crypto.Cipher import AES, DES3, Blowfish, ARC2
from Crypto.Hash import SHA256
from Crypto import Random
from tss import share_secret, reconstruct_secret, Hash, TSSError
import base64
import tss
import sys


def padtext1(user_input):
    while len(user_input) % 16 != 0:
        user_input += ' '
    return user_input


def padtext2(user_input):
    while len(user_input) % 8 != 0:
        user_input += b' '
    return user_input


def sha256(user_input):
    hasher = SHA256.new(user_input.encode('utf-8'))
    return hasher.digest()



# AES
def aes():
    plain_inputAES = input("Enter private key to be encrypted:\n")
    plain_length = len(plain_inputAES)
    print('Entered private key is ' + str(plain_length) + ' characters.')
    plainAES = padtext1(plain_inputAES)
    print('\nPrivate key after padding:')
    print(plainAES)
    print(len(plainAES))

    hasherAES = sha256(plainAES)
    print('\nHash of private key to be used as AES256 encryption key: ')
    print(hasherAES)
    print(len(hasherAES))

    global cipherAES
    cipherAES = AES.new(hasherAES)

    global ciphertextAES
    ciphertextAES = cipherAES.encrypt(plainAES)
    print('\nPrivate key after encrypting with AES256:')
    print(ciphertextAES)
    print(len(ciphertextAES))

    global executedAES
    executedAES = True



# Shamir's Secret Sharing
def shamir():
    secret = ciphertextAES
    print("Input to Shamir's Secret:")
    print(secret)
    print(len(secret))
    global t
    t=2
    s=3

    if len(sys.argv)>1:
        secret=str(sys.argv[1])
    if len(sys.argv)>2:
        t=int(sys.argv[2])
    if len(sys.argv)>3:
        s=int(sys.argv[3])

    global shares
    shares = tss.share_secret(t, s, secret, 'my-id', Hash.NONE)
    print("\n~~~~~ Key Split in 3 Shares ~~~~~")
    for x in range(0, s):
        print(shares[x])

    global constructedShamir
    constructedShamir = True



# DES3
def des3():
    print('Input to DES3:')
    plain_inputDES3 = shares[0]
    print(plain_inputDES3)
    print(len(plain_inputDES3))

    plainDES3 = padtext2(plain_inputDES3)
    print("\nShamir's secret 1 after padding:")
    print(plainDES3)
    print(len(plainDES3))

    while True:
        global DES3keyEn
        DES3keyEn = input('\nEnter a 24 characters DES3 encryption Key:\n')

        if len(DES3keyEn) < 24:
            print('Error: Entered Key is not 24 characters!')
        elif len(DES3keyEn) >= 25:
            print('Error: Entered Key is not 24 characters!')
        else:
            break

    print('\nEntered DES3 Key:\n' + DES3keyEn)

    cipherDES3 = DES3.new(DES3keyEn)

    global ciphertextDES3
    ciphertextDES3 = cipherDES3.encrypt(plainDES3)
    print("\nShamir's secret 1 after encrypting with DES3:")
    print(ciphertextDES3)
    print(len(ciphertextDES3))

    global executedDES3
    executedDES3 = True



# Blowfish
def blow():
    print('Input to Blowfish:')
    plain_inputBLOW = shares[1]
    print(plain_inputBLOW)
    print(len(plain_inputBLOW))

    plainBLOW = padtext2(plain_inputBLOW)
    print("\nShamir's secret 2 after padding:")
    print(plainBLOW)
    print(len(plainBLOW))

    while True:
        global BLOWkeyEn
        BLOWkeyEn = input('\nEnter a 56 characters Blowfish encryption Key:\n')

        if len(BLOWkeyEn) < 56:
            print('Error: Entered Key is not 56 characters!')
        elif len(BLOWkeyEn) >= 57:
            print('Error: Entered Key is not 56 characters!')
        else:
            break

    print('\nEntered Blowfish Key:\n' + BLOWkeyEn)

    cipherBLOW = Blowfish.new(BLOWkeyEn)

    global ciphertextBLOW
    ciphertextBLOW = cipherBLOW.encrypt(plainBLOW)
    print("\nShamir's secret 2 after encrypting with Blowfish:")
    print(ciphertextBLOW)
    print(len(ciphertextBLOW))

    global executedBLOW
    executedBLOW = True



# RC2
def rc2():
    print('Input to RC2:')
    plain_inputRC2 = shares[2]
    print(plain_inputRC2)
    print(len(plain_inputRC2))

    plainRC2 = padtext2(plain_inputRC2)
    print("\nShamir's secret 3 after padding:")
    print(plainRC2)
    print(len(plainRC2))

    while True:
        global RC2keyEn
        RC2keyEn = input('\nEnter a 64 characters RC2 encryption Key:\n')

        if len(RC2keyEn) < 64:
            print('Error: Entered Key is not 64 characters!')
        elif len(RC2keyEn) >= 65:
            print('Error: Entered Key is not 64 characters!')
        else:
            break

    print('\nEntered RC2 Key:\n' + RC2keyEn)

    cipherRC2 = ARC2.new(RC2keyEn)

    global ciphertextRC2
    ciphertextRC2 = cipherRC2.encrypt(plainRC2)
    print("\nShamir's secret 3 after encrypting with RC2:")
    print(ciphertextRC2)
    print(len(ciphertextRC2))

    global executedRC2
    executedRC2 = True



# Decrypting AES
def dcrpt_aes():
    plaintextAES = cipherAES.decrypt(ciphertextAES)
    stringAES = plaintextAES.replace(b' ', b'')
    print('Original private key after decrypting AES:')
    pvtkey = stringAES.decode()
    print(pvtkey)
    print(len(pvtkey))

    global decryptedAES
    decryptedAES = True



# Decrypting DES3
def dcrpt_des3():
    while True:
        DES3keyDe = input('Enter the 24 characters DES3 decryption Key:\n')

        if len(DES3keyDe) < 24:
            print('Error: Entered Key is not 24 characters!\n')
        elif len(DES3keyDe) >= 25:
            print('Error: Entered Key is not 24 characters!\n')
        else:
            if DES3keyDe == DES3keyEn:
                cipherDES3 = DES3.new(DES3keyDe)
                break
            else:
                print('Error: Wrong key was entered. Please try again!\n')

    plaintextDES3 = cipherDES3.decrypt(ciphertextDES3)
    stringDES3 = plaintextDES3.replace(b' ', b'')
    print("\nShamir's secret 1 after decrypting DES3:")
    print(stringDES3)
    print(len(stringDES3))

    global decryptedDES3
    decryptedDES3 = True



# Decrypting Blowfish
def dcrpt_blow():
    while True:
        BLOWkeyDe = input('Enter the 56 characters Blowfish decryption Key:\n')

        if len(BLOWkeyDe) < 56:
            print('Error: Entered Key is not 56 characters!\n')
        elif len(BLOWkeyDe) >= 57:
            print('Error: Entered Key is not 56 characters!\n')
        else:
            if BLOWkeyDe == BLOWkeyEn:
                cipherBLOW = Blowfish.new(BLOWkeyDe)
                break
            else:
                print('Error: Wrong key was entered. Please try again!\n')

    plaintextBLOW = cipherBLOW.decrypt(ciphertextBLOW)
    stringBLOW = plaintextBLOW.replace(b' ', b'')
    print("Shamir's secret 2 after decrypting Blowfish:")
    print(stringBLOW)
    print(len(stringBLOW))

    global decryptedBLOW
    decryptedBLOW = True



# Decrypting RC2
def dcrpt_rc2():
    while True:
        RC2keyDe = input('Enter the 64 characters RC2 decryption Key:\n')

        if len(RC2keyDe) < 64:
            print('Error: Entered Key is not 64 characters!\n')
        elif len(RC2keyDe) >= 65:
            print('Error: Entered Key is not 64 characters!\n')
        else:
            if RC2keyDe == RC2keyEn:
                cipherRC2 = ARC2.new(RC2keyDe)
                break
            else:
                print('Error: Wrong key was entered. Please try again!\n')

    plaintextRC2 = cipherRC2.decrypt(ciphertextRC2)
    stringRC2 = plaintextRC2.replace(b' ', b'')
    print("Shamir's secret 3 after decrypting RC2:")
    print(stringRC2)
    print(len(stringRC2))

    global decryptedRC2
    decryptedRC2 = True



# Decrypting Shamir's Secret Sharing
def dcrpt_shamir():
    reconstructed_secret1 = tss.reconstruct_secret(shares[0:t])
    print("Reconstructed by User and Provider:")
    print(reconstructed_secret1)

    reconstructed_secret2 = tss.reconstruct_secret(shares[0:t+1])
    print("\nReconstructed by All:")
    print(reconstructed_secret2)

    global reconstructShamir
    reconstructShamir = True



# Main function
if __name__ == "__main__":
    executedAES = False
    constructedShamir = False
    executedDES3 = False
    executedBLOW = False
    executedRC2 = False
    decryptedAES = False
    reconstructShamir = False
    decryptedDES3 = False
    decryptedBLOW = False
    decryptedRC2 = False

    while True:
        print("""
        ***** MENU *****
        1.  Enter Private key for encryption.
        2.  Split the Private key with Shamir's Secret Sharing.
        3.  Encrypt Secret 1 with DES3.
        4.  Encrypt Secret 2 with Blowfish.
        5.  Encrypt Secret 3 with RC2.
        6.  Decrypt Secret 1.
        7.  Decrypt Secret 2.
        8.  Decrypt Secret 3.
        9.  Reconstruct Shamir's Secret.
        10. Reconstruct Private Key.
        11. Exit/Quit
        """)
        ans = input("What would you like to do?\n")
        if ans == "1":
            if executedAES:
                print("Already executed!\nGo to Step 2.")
            else:
                print("\nHashing with SHA256 & encrypting with AES256:-")
                aes()
        elif ans == "2":
            if constructedShamir:
                print("Already executed!\nGo to Step 3.")
            elif not executedAES:
                print("First complete Step 1!")
            else:
                print("\nSplitting the key:-")
                shamir()
        elif ans == "3":
            if executedDES3:
                print("Already executed!\nGo to Step 4.")
            elif not constructedShamir:
                print("First complete Step 2!")
            else:
                print("\nEncrypting with DES3:-")
                des3()
        elif ans == "4":
            if executedBLOW:
                print("Already executed!\nGo to Step 5.")
            elif not constructedShamir:
                print("First complete Step 2!")
            else:
                print("\nEncrypting with Blowfish:-")
                blow()
        elif ans == "5":
            if executedRC2:
                print("Already executed!\nGo to Step 6.")
            elif not constructedShamir:
                print("First complete Step 2!")
            else:
                print("\nEncrypting with RC2:-")
                rc2()
        elif ans == "6":
            if decryptedDES3:
                print("Already executed!\nGo to Step 7.")
            elif not executedDES3:
                print("First complete Step 3!")
            else:
                print("\nDecrypting Secret 1:-")
                dcrpt_des3()
        elif ans == "7":
            if decryptedBLOW:
                print("Already executed!\nGo to Step 8.")
            elif not executedBLOW:
                print("First complete Step 4!")
            else:
                print("\nDecrypting Secret 2:-")
                dcrpt_blow()
        elif ans == "8":
            if decryptedRC2:
                print("Already executed!\nGo to Step 9.")
            elif not executedRC2:
                print("First complete Step 5!")
            else:
                print("\nDecrypting Secret 3:-")
                dcrpt_rc2()
        elif ans == "9":
            if reconstructShamir:
                print("Already executed!\nGo to Step 10.")
            elif not decryptedDES3 or not decryptedBLOW or not decryptedRC2:
                print("First complete Steps 6,7, and 8!")
            else:
                print("\nReconstructing Secret:-")
                dcrpt_shamir()
        elif ans == "10":
            if decryptedAES:
                print("Already executed!\nYou can Exit/Quit the program.")
            elif not reconstructShamir:
                print("First complete Step 9!")
            else:
                print("\nReconstructing Private Key:-")
                dcrpt_aes()
        elif ans == "11":
            print("Goodbye!")
            break
        elif ans != "":
            print("Enter a valid choice & try again!")