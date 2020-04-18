#!/usr/bin/env python3
from requests import get
from bs4 import BeautifulSoup
import re
import sys
import time

pattern = re.compile('Decimal')
fib_url = 'http://www.protocol5.com/Fibonacci/{}.htm'
local_url = 'http://localhost:8081/fib/{}'

RED = '\033[91m'
GREEN = '\033[92m'
WHITE = '\033[0m'

def printInColor(content, color = WHITE, end = '\n'):
	print(color + content, end = end)

def getFib(n):
	content = get(fib_url.format(n))
	soup = BeautifulSoup(content.text, 'lxml')
	fib = soup.find('h4', text = pattern).findNext('div')
	return fib.text

# main function
try:
	n = int(sys.argv[1])
	
	start = time.time()
	data = get(local_url.format(n))
	end = time.time()

	ans = getFib(n)

	printInColor('+++\tVerify the result of Fibonacci({})\n'.format(n));

	if data.text == ans:
		printInColor('---\tCorrect!', GREEN)
	else:
		printInColor('---\tYour answer: \t' + data.text)
		printInColor('---\tAnswer: \t' + ans)
		printInColor('---\tWrong', RED)

	print()
	printInColor('time cost: {}'.format(end - start))

except:
	printInColor('[ERROR] Failed to connect to the server.', RED)
