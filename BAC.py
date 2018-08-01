import http.client
from base64 import b64encode

#import urllib
#import urllib2

connection = http.client.HTTPConnection('localhost', 9010, timeout=10)
userAndPass = "username:password" #b64encode(b"username:password").decode("ascii")
#userAndPass = "hello:world" 
#userAndPass = b64encode(b"hello:world") 
#userAndPass = b64encode(b"username:password").decode("ascii")
#print(userAndPass)
headers = { 'Authorization' : 'Basic %s' %  userAndPass }
connection.request("GET", "/foo", headers=headers)
response = connection.getresponse()
print("Status: {} and reason: {}".format(response.status, response.reason))

connection.close()
