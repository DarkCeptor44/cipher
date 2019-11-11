# Cipher

Encrypts and Decrypts any `.txt` file in the current directory when a password is provided (unless the names of the files are specified in the `EXCEPTIONS` array).
Useful to hide text from people with either physical or remote access to your machine, you can use for diaries (just an example).

## How to use

 1. Download `cipher.py` to your machine.
 2. Open a command prompt on the directory where `cipher.py` is:
 3. Type `python` , press Enter, type `import os; os.urandom(16)` , press Enter and copy the line that shows up (it looks like `b'xxxxxxxxxxxxxxxxxxx'` )
 4. Open `cipher.py` and look for line 58 where it says `salt = b'xxxxxxxxxxxxxxx'` , then just paste that line you copied after the `=` .
 5. Save it and run it to encrypt the `.txt` files that are in the same directory.

## Notes

* You can use any password on encryption but if you try to decrypt with a different password than you used it's gonna give an error.
* I recommend use of [auto-py-to-exe](https://github.com/brentvollebregt/auto-py-to-exe) to compile `.py` in `.exe` which makes it harder for someone to see the code.

## Download

If you don't care about the security of generating your own salt then you can download a version that comes with a pre-generated salt, links are on the [Releases](https://github.com/DarkCeptor44/cipher/releases) tab.

### This script is meant for less tech-savvy people as it's not highly advanced but can be modified to whatever you need
