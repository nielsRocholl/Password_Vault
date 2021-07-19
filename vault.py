import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial

# Database Code
with sqlite3.connect('vault.db') as db:
    cursor = db.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL, 
username TEXT NOT NULL,
password TEXT NOT NULL);
''')


# Create pop-up
def popUp(text):
    answer = simpledialog.askstring('Input String', text)

    return answer


# Window Code
mainColor = '#2c7c9a'
window = Tk()
window.title('Password Vault')
window['bg'] = mainColor


def hashPassword(input):
    hash = hashlib.md5(input)
    hash = hash.digest()

    return hash


def firstScreen():
    window.geometry('250x150')

    lbl1 = Label(window, text='Create Master Password')
    lbl1.config(anchor=CENTER, bg=mainColor)
    lbl1.pack()

    txt = Entry(window, width=20, show='*')
    txt.pack()
    txt.focus()

    lbl2 = Label(window, text='Re-Enter Password')
    lbl2.config(anchor=CENTER, bg=mainColor)
    lbl2.pack()

    txt1 = Entry(window, width=20, show='*')
    txt1.pack()
    txt1.focus()

    lbl3 = Label(window, bg=mainColor)
    lbl3.pack()

    def savePassword():
        if txt.get() == txt1.get():
            hashedPassword = hashPassword(txt.get().encode('utf-8'))
            insert_password = '''INSERT INTO masterpassword(password) VALUES(?) '''
            cursor.execute(insert_password, [(hashedPassword)])
            db.commit()
            passwordVault()

        else:
            lbl3.config(anchor=CENTER, text='Passwords Do Not Match!', bg='#a64747')

    btn = Button(window, text='Save', bg='#466d88', command=savePassword)
    btn.pack(pady=10)


def loginScreen():
    window.geometry('250x100')

    lbl1 = Label(window, text='Enter The Master Password')
    lbl1.config(anchor=CENTER, bg=mainColor)
    lbl1.pack()

    txt = Entry(window, width=20, show='*')
    txt.pack()
    txt.focus()

    lbl2 = Label(window)
    lbl2.config(anchor=CENTER, bg=mainColor)
    lbl2.pack(side=TOP)

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND password = ?', [(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword():
        match = getMasterPassword()

        if match:
            passwordVault()
        else:
            txt.delete(0, 'end')
            lbl2.config(anchor=CENTER, text='Password Incorrect!', bg='#a64747')

    btn = Button(window, text='Submit', bg='#466d88', command=checkPassword)
    btn.pack(pady=10)


def passwordVault():
    window.geometry('800x400')

    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        website = popUp('Website')
        username = popUp('Username')
        password = popUp('Password')

        fields = '''INSERT INTO vault(website, username, password) VALUES(?, ?, ?)'''
        cursor.execute(fields, (website, username, password))
        db.commit()
        passwordVault()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        passwordVault()

    # lbl1 = Label(window, text='Password Vault')
    # lbl1.grid(column=1)

    btn = Button(window, text='+', command=addEntry)
    btn.grid(column=0, pady=40)

    lbl = Label(window, text='Website')
    lbl.grid(row=2, column=0, padx=80)

    lbl = Label(window, text='Username')
    lbl.grid(row=2, column=1, padx=80)

    lbl = Label(window, text='Password')
    lbl.grid(row=2, column=2, padx=80)

    cursor.execute('SELECT * FROM vault')
    if cursor.fetchall() is not None:
        i = 0
        while True:
            cursor.execute('SELECT * FROM vault')
            array = cursor.fetchall()
            lbl1 = Label(window, text=(array[i][1]), font=('Helvetica', 12))
            lbl1.grid(column=0, row=i + 3)
            lbl1 = Label(window, text=(array[i][2]), font=('Helvetica', 12))
            lbl1.grid(column=1, row=i + 3)
            lbl1 = Label(window, text=(array[i][3]), font=('Helvetica', 12))
            lbl1.grid(column=2, row=i + 3)

            btn = Button(window, text='Delete', command=partial(removeEntry, array[i][0]))
            btn.grid(column=3, row=i + 3, pady=10)

            i += 1

            cursor.execute('SELECT * FROM vault')
            if len(cursor.fetchall()) <= i:
                break


cursor.execute('SELECT * FROM masterpassword')

if cursor.fetchall():
    loginScreen()
else:
    firstScreen()

window.mainloop()
