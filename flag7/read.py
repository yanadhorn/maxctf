#!/usr/bin/python
import os

for filename in os.listdir("/root/"):
	print (filename)
	f = open('/root/'+filename,'r')
	message = f.read()
	print(message)
	f.close()
