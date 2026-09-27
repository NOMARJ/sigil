# Synthetic fixture: a Windows executable carried as a bytes literal and dropped to disk.
import os

f = open(os.path.join(os.getenv('TEMP', '/tmp'), 'helper.exe'), 'wb')
f.write(b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00')
f.close()
