import socket
import random
import string
 
size = 8192

def randomStr(length):
  myStr = ''
  for i in range(length):
    myStr = myStr + random.choice(string.ascii_letters)
  return myStr

try:
  # msg = input().encode()
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

  for i in range (51):
    msg = randomStr(random.randint(5, 20)).encode()
    print ("发送消息：" + str(i), msg)
    sock.sendto(msg, ('localhost', 9876))
    print (sock.recv(size))
  
  sock.close()
 
# except:
#   print ("cannot reach the server")

except Exception as e:
  print (e)