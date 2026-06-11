import base64
import subprocess


def run():
    eval("1 + 1")
    exec("print('hello')")
    payload = base64.b64decode("aGVsbG8=")
    subprocess.call("ls -la", shell=True)
    return payload
