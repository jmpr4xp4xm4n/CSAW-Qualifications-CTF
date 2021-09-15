from pwn import *
from subprocess import *

io = remote("pwn.chal.csaw.io", 5002)
guess = check_output(["./guess"])
io.sendline(guess)
io.interactive()
