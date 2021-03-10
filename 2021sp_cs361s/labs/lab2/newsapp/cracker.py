import sqlite3
import cryptography
import sys
from string import ascii_lowercase
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

common_pws = ['123456', '123456789', 'qwerty', 'password', '1234567', 
'12345678', '12345', 'iloveyou', '111111', '123123', 'abc123', 'qwerty123',
'1q2w3e4r', 'admin', 'qwertyuiop', '654321', '555555', 'lovely', '7777777', 
'welcome', '888888', 'princess', 'dragon', 'password1', '123qwe']

def encrypt(iterations, salt, password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=iterations)
    utfencoded = password.encode()
    key = kdf.derive(utfencoded)
    return base64.b64encode(key)

if len(sys.argv) == 2:
    db_entry = sys.argv[1].split('$')
    iterations = int(db_entry[1])
    if iterations == 1:
        salt = db_entry[2]
        myHash = db_entry[3].encode()
        # print("myHash: ", myHash)
        # iterate through alphabet stuff
        #len 1
        for c in ascii_lowercase:
            pwstring =  c
            # do the algorithm
            tryhash = encrypt(iterations, salt, pwstring)
            # print("pw: ", pwstring, "    tryhash: ", tryhash)
            if str(tryhash) == str(myHash):
                print("password cracked: ", pwstring)
                exit()
        #len 2
        for c in ascii_lowercase:
            for d in ascii_lowercase:
                pwstring = "" + c + d
                # do the algorithm
                tryhash = encrypt(iterations, salt, pwstring)
                if str(tryhash) == str(myHash):
                    print("password cracked: ", pwstring)
                    exit()
        #len 3
        for c in ascii_lowercase:
            for d in ascii_lowercase:
                for e in ascii_lowercase:
                    pwstring = "" + c + d + e
                    tryhash = encrypt(iterations, salt, pwstring)
                    if str(tryhash) == str(myHash):
                        print("password cracked: ", pwstring)
                        exit()
        #len 4
        for c in ascii_lowercase:
            for d in ascii_lowercase:
                for e in ascii_lowercase:
                    for f in ascii_lowercase:
                        pwstring = "" + c + d + e + f
                        tryhash = encrypt(iterations, salt, pwstring)
                        if str(tryhash) == str(myHash):
                            print("password cracked: ", pwstring)
                            exit()
    else:
        print("Cannot brute-force password in time.")
elif len(sys.argv) == 1:
    # get entries
    con = sqlite3.connect('db.sqlite3')
    cursor = con.cursor()
    cursor.execute("SELECT * FROM auth_user")
    entries = cursor.fetchall()

    for entry in entries:
        user = entry[4]
        # print(entry)
        hash_array = entry[1].split('$')
        iterations = int(hash_array[1])
        salt = hash_array[2]
        myHash = hash_array[3].encode()

        #try every password
        for pw in common_pws:
            tryhash = encrypt(iterations, salt, pw)
            if str(tryhash) == str(myHash):
                print(user, ", ", pw)
                break




else:
    print("wrong number of arguments")

# con = sqlite3.connect('db.sqlite3')
# cursor = con.cursor()
# # cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
# # print(cursor.fetchall())

# cursor.execute("SELECT * FROM auth_user")
# # print(cursor.fetchall())
# # for thing in cursor.fetchall():
# #     # print(thing)
# #     query = thing[1]
# #     myHash = query.split('$')[3]
# #     print(myHash)
# #     # print(myHash)
# #     print(base64.b64decode(myHash.strip()))
# print(encrypt(1, b'salt', 'password'))

    # print(type(thing))