from pwn import *

connection = remote('titan.picoctf.net', 61924)

#Get the first messages and send encrypt
response = connection.recvuntil('decrypt.')
print(response.decode())
payload = b'E' + b'\n'

connection.send(payload)

response = connection.recvuntil('keysize):')
print(response.decode())

#We want to encrypt the number 2
payload = b'\x02' + b'\n'
connection.send(payload)
response = connection.recvuntil('ciphertext (m ^ e mod n)')
response = connection.recvline()

#We now have 2^e, we want to multiply by m^e (from the file password.enc)
num=int(response.decode())*3567252736412634555920569398403787395170577668834666742330267390011828943495692402033350307843527370186546259265692029368644049938630024394169760506488003

#We now choose to decrypt
response = connection.recvuntil('decrypt.')
print(response.decode())
payload = b'D' + b'\n'
connection.send(payload)

#We decrypt 2^e*m^e, which will yield 2*m
response = connection.recvuntil('decrypt:')
print(response.decode())
connection.send(str(num)+'\n')

response = connection.recvuntil('hex (c ^ d mod n):')
print(response.decode())
response = connection.recvline()
print(response.decode())

#we grab the response, convert it from hexadecimal and divide by 2
num=int(response,16)//2
print(hex(num))

#Now we convert this to ASCII
hex_string=hex(num)[2:] # get rid of 0x
byte_array=bytes.fromhex(hex_string)
print(byte_array.decode('ascii'))

#Close the connection
connection.close()

