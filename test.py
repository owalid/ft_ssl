import re
import os
from colorama import Fore, Style

def allEqual(liste):
	for regex in liste:
		if regex != liste[0]:
			return False
	return True

def runCommands(algo, stdin, name):
	# open('.test', 'w').write(stdin)
	myStdout = os.popen(f'echo -n "{stdin}" | ./ft_ssl {algo} -s "{stdin}" -p').read()
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
	for algo in ['md5']:
		runCommands(algo, stdin, name)

for index in range(150):
	testAlgos('A' * index, f"'A' * {index}")

# testAlgos('A' * 100000 , f"'A' * 10000")