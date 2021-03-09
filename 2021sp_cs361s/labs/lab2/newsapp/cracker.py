import sqlite3
import cryptography
import sys
from string import ascii_lowercase
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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
    print("blah")
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