import socket

size = 8192

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('', 9876))       

try:
  num = 0
  while True:
    data, address = sock.recvfrom(size)
    data = data.decode()
    print ("服务端收到", data)
    data = (str(num) + ' ' + data).encode()
    num = num + 1
    sock.sendto(data.upper(), address)
    print ("服务端已发送")
finally:
  sock.close()