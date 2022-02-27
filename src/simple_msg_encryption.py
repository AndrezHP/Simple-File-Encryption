import os
from cryptography.fernet import Fernet

def test_enc_dec_msg():
    msg_loc = "msg.secret"
    msg = "This is a secret" # to encrypt

    # gen key, if not already there, then read it
    gen_rand_key('key.key')
    key = read_from_file('key.key')
    
    encrypt_msg(msg_loc, msg, key) 
    msg_dec = decrypt_msg(msg_loc, key)

    if msg == msg_dec: print("TEST PASS")
    else: print("TEST FAIL")

def encrypt_msg(loc, msg, key):
    # gen fernet object
    f = Fernet(key)
    encoded_msg = msg.encode()
    encrypted = f.encrypt(encoded_msg)
    
    # write to file
    write_to_file(loc, encrypted)

def decrypt_msg(loc, key):
    f = Fernet(key)
    # read from file
    encrypted_msg = read_from_file(loc)

    # decrypt and decode
    msg_decrypted = f.decrypt(encrypted_msg).decode()

    return msg_decrypted

################

# generate random key and write to location
def gen_rand_key(loc):
    if os.path.exists(loc):
        return
    key = Fernet.generate_key()
    write_to_file(loc, key)

# read from file
def read_from_file(loc):
    file = open(loc, 'rb')
    content = file.read()
    file.close()
    return content

# wrote to file
def write_to_file(loc, content):
    file = open(loc, 'wb')
    file.write(content)
    file.close

################

def main():
    test_enc_dec_msg()

if __name__ == '__main__':
    main()