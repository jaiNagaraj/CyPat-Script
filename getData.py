from bs4 import BeautifulSoup
import sys

user = sys.argv[1]
with open("C:/Users/%s/Desktop/USACO.html" %user) as file:
    soup = BeautifulSoup(file,'html.parser')

output = open("C:/Users/%s/Desktop/output.txt" %user,'w')

wordList = str(soup.get_text()).strip('./:\n ()').split()
count = 0
for word in wordList:
    if word == "Vivian":
        count += 1

print(count)