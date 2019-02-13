##### WRITTEN BY: EDWIN CERVANTES
##### CSCI 240
##### PASSWORD CRACKER WRITTEN IN PYTHON TO CRACK A SET OF PASSWORDS WITH GIVEN RULES. FULL OUTLINE OF PROJECT BELOW.
#####Objective: get a feel for how a password cracking program works; get a better understanding of one-way encryption.



from hashlib import sha256


##Reads in the passwords and usernames given to us in the fom of username:encryption
users = open("/home/edwin/CSCI240/Homework/passCrackExamples.txt","r")
listed = []



#Checks for any length single word from /usr/share/dict/words
def singleWord():
    words = open("/usr/share/dict/words","rb")
    wordList = []
    wordListEncrypt = []
    i = 0
    index = 0
    for line in words:
        passwd = line.strip()
        wordList.append(passwd)
    while i < len(wordList):
        word = wordList[i]
        hash_word = sha256(word.rstrip()).hexdigest()
        wordListEncrypt.append(hash_word)
    #    print(wordListEncrypt[i])
        i+=1
    while index < len(wordListEncrypt):
        if wordListEncrypt[index] == encryptedPass:
            listed.append(wordList[index])
        index+=1
    words.close()


#Checks for any word that is made with up to 6 digits

def sixDigits():
    numbers = []
    numbersEncrypt = []
    i = 0
    j = 0
    index = 0
    while i < 1000000:
        x = str(i)
        numbers.append(x)
        i+=1
    while j < len(numbers):
        number = numbers[j]
        hash_word = sha256(number.rstrip()).hexdigest()
        numbersEncrypt.append(hash_word)
        j += 1
    while index < len(numbersEncrypt):
        if numbersEncrypt[index] == encryptedPass:
            listed.append(numbers[index])
        index += 1



#A five char word where a gets replaced with @ and l gets replaced with 1
def fiveChar():
    print("enters")
    words = open("/usr/share/dict/words","rb")
    fiveChar = []
    fiveCharEncrypted = []
    i = 0
    j = 0
    for line in words:
        index = 0
        word = line.strip()
        if len(word) == 5:
            list(word)
            for index in xrange(len(word)):
                if word[index] == "a":
                    word[index] = "@"
                if word[index] == 'l':
                    word[index] = '1'
            makeitastring = ''.join(map(str, word))
            index += 1
        fiveChar.append(word)
    while i < len(fiveChar):
        word = fiveChar[i]
        hash_word = sha256(word.rstrip()).hexdigest()
        fiveCharEncrypted.append(hash_word)
        i+=1
    while j < len(fiveCharEncrypted):
        if fiveCharEncrypted[j] == encryptedPass:
            listed.append(fiveChar[index])
        j += 1
    words.close()



#Checks for 4 digit password with a special character at the beginning *,!,~,#
def fourDigits():

        numbers = []
        numbersEncrypt = []
        i = 0
        j = 0
        index = 0
        while i < 10000:
            x = "~" + str(i)
            numbers.append(x)
            i+=1
        i = 0
        while i < 10000:
            x = "!" + str(i)
            numbers.append(x)
            i+=1
        i = 0
        while i < 10000:
            x = "#" + str(i)
            numbers.append(x)
            i+=1
        i = 0
        while i < 10000:
            x = "*" + str(i)
            numbers.append(x)
            i+=1
        i = 0
        while j < len(numbers):
            number = numbers[j]
            hash_word = sha256(number.rstrip()).hexdigest()
            numbersEncrypt.append(hash_word)
            j += 1
        while index < len(numbersEncrypt):
            if numbersEncrypt[index] == encryptedPass:
                listed.append(numbers[index])
            index += 1


#Checks for a seven char word from /usr/share/dict/words (Linux or Mac) which gets the first letter capitalized and a 1-digit number appended.

def sevenChar():
    words = open("/usr/share/dict/words","rb")
    sevenChar = []
    sevenCharEncrypted = []
    index = 0
    j = 0
    for line in words:
        word = line.rstrip()
        if len(word) == 7:
            word.capitalize()
            i = 0
            while i < 9:
                x = str(i)
                word = word + x
                sevenChar.append(word)
                i += 1
    while j < len(sevenChar):
        word = sevenChar[j]
        hash_word = sha256(word.rstrip()).hexdigest()
        sevenCharEncrypted.append(hash_word)
        j+=1
    while index < len(sevenCharEncrypted):
        if sevenCharEncrypted[index] == encryptedPass:
            listed.append(sevenChar[index])
        index += 1
    words.close()

def checkTest():

    singleWord()

    sevenChar()

    sixDigits()

#    fiveChar()

    fourDigits()

#Cracks one username/password combo at a time before moving onto the next
#First read in user and split username and encryption into two using .split

for line in users:
    password = line.rstrip()
    userName = password.split(":", 1)[0]
    encryptedPass = password.split(":", 1)[1]
    checkTest()


for x in listed:
    print(x)
