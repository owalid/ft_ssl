import re
import os
from colorama import Fore, Style

def allEqual(liste):
	for regex in liste:
		if regex != liste[0]:
			return False
	return True

def runCommands(algo, stdin, name):
	open('.test', 'w').write(stdin)
	if (len(stdin) < 500):
		myStdout = os.popen(f'echo -n "{stdin}" | ./ft_ssl {algo} -s "{stdin}" -p .test').read()
	else:
		myStdout = os.popen(f'cat .test | ./ft_ssl {algo} -p .test').read()
	hisStdout = os.popen(f'echo -n "{stdin}" | openssl {algo}').read()

	myHash = re.findall(r'([a-f0-9]{10,})', myStdout)
	hisHash = re.findall(r'([a-f0-9]{10,})', hisStdout)[0]
	if (myHash[0] == hisHash and myHash[0] != '' and myHash[0] != None and allEqual(myHash)):
		# print(Fore.GREEN, end='')
		# print(f'{algo}("{name}"): OK\'')
		pass
	else:
		print(Fore.RED, end='')
		print('============= FAIL ===============')
		print(algo)
		print(name)
		print(stdin)
		for oneHash in myHash:
			print('ft_ssl: ', oneHash)
		print('openssl:', hisHash)
		print('============= FAIL ===============')
	print(Style.RESET_ALL, end='')

def testAlgos(stdin, name):
	for algo in ['md5', 'sha224', 'sha256', 'sha384', 'sha512']:
		runCommands(algo, stdin, name)

for index in range(260):
	testAlgos('A' * index, f"'A' * {index}")

# testAlgos('A' * 100000 , f"'A' * 10000")