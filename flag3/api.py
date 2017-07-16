#!/usr/bin/env python3

import urllib.request
from bs4 import BeautifulSoup

def getIDList(url):
	IDList = []

	with urllib.request.urlopen(url) as response:
		html = response.read()

	soup = BeautifulSoup(html, 'html.parser')
	
	for patID in soup.find_all('option'):
		IDList.append(patID.get("value"))

	return IDList

def main():
	IDList = getIDList("http://10.13.37.4/")

	for patID in IDList:
		url = "http://10.13.37.4/api/viewPatient?password=mTvkHrQdaPHLp477&patientID=" + patID
		with urllib.request.urlopen(url) as response:
			html = response.read()
			print(html)

if __name__ == "__main__":
	main()
