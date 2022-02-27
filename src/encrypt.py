import base64, os, sys
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

################

# generate random key and write to location
def gen_rand_key(loc):
    if os.path.exists(loc):
        return
    key = Fernet.generate_key() 
    print("New key generated")
    write_to_file(loc, key)

def read_from_file(loc):
    file = open(loc, 'rb')
    content = file.read()
    file.close()
    return content

def write_to_file(loc, content):
    file = open(loc, 'wb')
    file.write(content)
    file.close

################

def pw_keygen(pw):
    pw_enc = pw.encode()
    salt = "eL\x96\xd5P:\xfe\xa2\xd7\x8e$\xebW\xf1GJ".encode()

    kdf = PBKDF2HMAC(algorithm=hashes.SHA256, length=32, salt=salt, iterations=100000, backend=default_backend)
    key = base64.urlsafe_b64encode(kdf.derive(pw_enc))

    return key

def encrypt(loc, key):
    # gen fernet object
    f = Fernet(key)

    # read from file
    msg = read_from_file(loc)

    # encrypt and write to file
    encrypted = f.encrypt(msg)
    write_to_file(loc, encrypted)

def decrypt(loc, key):
    # gen fernet object
    f = Fernet(key)
    
    # read from file and decrypt
    encrypted_msg = read_from_file(loc)
    decrypted_msg = f.decrypt(encrypted_msg)

    # write to file
    write_to_file(loc, decrypted_msg)

def recursive_file_iter(loc, func, key):
    # if only single file
    if os.path.isfile(loc):
        func(loc, key)
        return
    
    for root, _, files in os.walk(loc):
        for filename in files:
            file = root + "\\" + filename
            try:
                func(file, key)
            except:
                print("Error: could not " + str(func)[10:17] + ":", file)

def main():
    key = None
    function = str(sys.argv[1])
    loc = str(sys.argv[2])
    
    if len(sys.argv) > 3: # use password based encryption if included as argument
        pw = str(sys.argv[3])
        key = pw_keygen(pw)
    else: # gen key, if not already there, then read it
        gen_rand_key('key.key')
        key = read_from_file('key.key')

    if function == "-e":
        recursive_file_iter(loc, encrypt, key)
    elif function == "-d":
        recursive_file_iter(loc, decrypt, key)

if __name__ == '__main__':
    main()

'''
[x] add location specification on script call
[x] add recursive directory file iteration
[x] choose encryption (-e) or decryption (-d) on script call
'''