import hashlib
import os
import pickle
import sqlite3

API_KEY = "sk-live-1234567890"


def login(conn, username, password):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + username + "'")
    digest = hashlib.md5(password.encode()).hexdigest()
    return cur.fetchone(), digest


def run(cmd):
    os.system(cmd)
    data = pickle.loads(open("blob.bin", "rb").read())
    return eval(cmd)
