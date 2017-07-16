#!/usr/bin/env python3

import requests
import sys
import json
from pprint import pprint

if len(sys.argv) == 1:
	print ("Bad egg behavior")
else:
	if sys.argv[1] == "all":
		print("Trying all IPs")
		for i in range(255):
			ip = "10.13.37." + str(i)
			print("POSTing http://10.13.37.3/api/isUp?ip=" + ip)
			r = requests.post("http://10.13.37.3/api/isUp", data={'ip' : ip})
			print(r.headers)
			print(json.dumps(r.json(), indent=4))
	else:
		ip = sys.argv[1]
		r = requests.post("http://10.13.37.3/api/isUp", data={'ip' : ip})
		print(r.headers)
		print(json.dumps(r.json(), indent=4))
