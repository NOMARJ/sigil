# Synthetic fixture: browser credential store opened for decryption on one
# line (infostealer shape, MITRE T1555.003). No real tokens in this file.
import os
import sqlite3

conn = sqlite3.connect(os.path.expanduser("~/Library/Application Support/Google/Chrome/Default/Login Data"))
