import sys
import base64
import os
import json
import ctypes
import tkinter as tk
from tkinter import messagebox
import gspread
import pyperclip
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from oauth2client.service_account import ServiceAccountCredentials

logger = logging.getLogger(__name__)
logging.basicConfig(filename='cerra.log',
    filemode='w',
    level=logging.NOTSET,
    format='%(asctime)s - %(levelname)s - %(message)s'
    )

def my_handler(type, value, tb):
    logger.exception("Uncaught exception: {0}".format(str(value)))

sys.excepthook = my_handler

class Clouded:
    decidingBool = False
    startpoint = None

    def __init__(self, detroy):
        """Checks whether the program can acces the API, for whatever
        reason it fails, the Request button will be disabled"""
        scope = ["https://www.googleapis.com/auth/drive"]
        self.detroy = detroy

        try:
            Clouded.creds = ServiceAccountCredentials.from_json_keyfile_name('client_secret.json', scope)
        except Exception as e:
            logger.error(e)
            messagebox.showinfo('Error', 'No Network Connection')
            self.detroy.config(state="disabled")
            return
        else:
            Clouded.decidingBool = True

        Clouded.client = gspread.authorize(self.creds)
        Clouded.sheet = Clouded.client.open('food').sheet1

    @classmethod
    def tesesame(cls, name, passnoun, event=None):
        """This is the function that checks wether an online password
        and named ID are correct"""
        if Secretsasfuck.restrictions(passnoun.get()):
            print("red")
            return
        elif not bool(name.get()):
            logger.error("no name placed")
            messagebox.showerror("No Name", "You didn't write the Name ID")
            return
        else:
            print("blue")
            Secretsasfuck.assword = passnoun.get()

        values_list = cls.sheet.row_values(1)
        try:
            cls.startpoint = values_list.index(name.get()) + 1
        except:
            messagebox.showerror("error 404",'There is no password set under the name: ' + '"' + name.get() + '"')
            return
        else:
            pass

        print("not again")
        service_column = cls.sheet.col_values(cls.startpoint)

        if not bool(cls.sheet.cell(1, cls.startpoint + 1).value):
            Secretsasfuck.create_salt()
            Secretsasfuck.salt = cls.sheet.cell(1, cls.startpoint + 1).value.encode()
            Secretsasfuck.generate_fernet()
            messagebox.showinfo("First Time", "Once you save a password the master will be saved")
            Onlygui.menu()

        elif len(service_column) == 1:
            messagebox.showinfo("First Time", "Once you save a password the master will be saved")
            Secretsasfuck.salt = cls.sheet.cell(1, cls.startpoint + 1).value.encode()
            Secretsasfuck.generate_fernet()
            Onlygui.menu()

        else:
            Secretsasfuck.salt = cls.sheet.cell(1, cls.startpoint + 1).value.encode()
            Secretsasfuck.generate_fernet()
            password_column = cls.sheet.col_values(cls.startpoint + 1)
            Secretsasfuck.rawData = dict(zip(service_column[1:], password_column[1:]))
            Secretsasfuck.test_this_password()

    @classmethod
    def heaven(cls, serf, keye):
        """Sends a new password and service name to the database"""
        cls.sheet.update_cell(len(cls.sheet.col_values(cls.startpoint)) + 1, cls.startpoint, serf)
        cls.sheet.update_cell(len(cls.sheet.col_values(cls.startpoint + 1)) + 1, cls.startpoint + 1, keye)

    @classmethod
    def hell(cls, part):
        """deletes a row based on the password wanted to be delete_password
        from the online database"""
        reference = list(part.keys())
        flist = cls.sheet.col_values(cls.startpoint)
        cls.sheet.update_cell(len(flist), cls.startpoint, "")
        cls.sheet.update_cell(len(flist), cls.startpoint + 1, "")
        for x, y in part.items():
            cls.sheet.update_cell(reference.index(x) + 2, cls.startpoint, x)
            cls.sheet.update_cell(reference.index(x) + 2, cls.startpoint + 1, y.decode())

    @classmethod
    def change_heaven(cls, oldy, smally):
        """Replaces only the password for a given service based on
        the service wanted to edit"""
        flist = cls.sheet.col_values(cls.startpoint + 1)
        cls.sheet.update_cell(flist.index(oldy) + 1, cls.startpoint + 1, smally)

    @classmethod
    def distort_heaven(cls):
        """Only changes the way that the passwords are encrypted
        based on the new master password and a new salt"""
        row = 2
        for key, pas in Secretsasfuck.rawData.items():
            cls.sheet.update_cell(row, cls.startpoint, key)
            cls.sheet.update_cell(row, cls.startpoint + 1, pas.decode())
            row += 1

class Secretsasfuck:
    assword = None
    key = None
    passwordDict = {}
    jsondata = {}
    rawData = {}
    magic_string = "MGKSTRG"
    salt = None
    fernet = None

    def __init__(self, assword):
        """Checks whether A, Both files exist like the salt and the
        password file, B one of them exists the other doesn't"""
        Secretsasfuck.assword = assword

        if self.restrictions(assword):
            return
        else:
            pass


        if not os.path.exists("password_dict.json"):
            alcohol = open("password_dict.json", "w")
            alcohol.write("{}")
            alcohol.close()

        json_file = open("password_dict.json", "r")
        try:
            Secretsasfuck.jsondata = json.load(json_file)
        except Exception as e:
            logger.error(e)
            Secretsasfuck.jsondata = {}
        else:
            pass
        json_file.close()

        if bool(Secretsasfuck.jsondata) and os.path.exists("salt.txt"):
            logger.info("salt and passwords existant")
            with open("salt.txt", "rb") as gay:
                Secretsasfuck.salt = gay.read()
            self.correct_password()
        elif os.path.exists("salt.txt"):
            logger.info("only salt existant")
            Secretsasfuck.rawData = {}
            with open("salt.txt", "rb") as gay:
                Secretsasfuck.salt = gay.read()
            self.generate_fernet()
            messagebox.showinfo("First Time", "Once you save a password the master will be saved")
            Onlygui.menu()
        elif bool(Secretsasfuck.jsondata):
            logger.error("No salt exists, sadly the password set must be deleted")
            messagebox.showerror('Unexpected', 'it appears some files were corrupted or deleted \n all your saves will have to be deleted')
            with open('password_dict.json', 'w') as sorry:
                sorry.write('{}')
            self.create_salt()
            with open("salt.txt", "rb") as st:
                Secretsasfuck.salt = st.read()
            Onlygui.menu()
        else:
            self.create_salt()
            with open("salt.txt", "rb") as st:
                Secretsasfuck.salt = st.read()
            messagebox.showinfo("First Time", "Once you save a password the master will be saved")
            Onlygui.menu()

    @classmethod
    def restrictions(cls, stringy):
        """Checks whether a string can fit the restrictions of the master password
        and return True if it doesn't"""
        if " " in stringy:
            logger.info("password has spaces return to menu")
            messagebox.showerror("...", "password must not have spaces")
            return True

        if not len(stringy) >= 8:
            logger.info("password is shorter than 8 return to menu")
            messagebox.showerror("...", "password must be 8 characters or longer")
            return True

    def correct_password(self):
        """Intermediate function"""
        logger.warning("organizing password")
        self.organize()
        self.test_this_password()

    def organize(self):
        """takes out the defining string of the encrypted passwords"""
        Secretsasfuck.rawData = dict(map(lambda x: (x[0], x[1].replace(self.magic_string,"")),Secretsasfuck.jsondata.items()))

    @classmethod
    def generate_fernet(cls):
        """Generates fernet from a salt and the provided password"""
        kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=cls.salt,
        iterations=100000,
        backend=default_backend()
        )

        try_key = base64.urlsafe_b64encode(kdf.derive(cls.assword.encode()))
        cls.fernet = Fernet(try_key)
        cls.key = try_key

    @classmethod
    def test_this_password(cls):
        """Tries the password to see if it works, will show a messagebox if
        it doesn't or else it will lead to the menu"""
        cls.generate_fernet()

        tester = cls.rawData[next(iter(cls.rawData))]

        logger.debug("This is the encrypted being tested " + tester)

        try:
            cls.fernet.decrypt(tester.encode())
        except Exception as e:
            logger.error(e)
            messagebox.showwarning("...","INCORRECT PASSWORD")
            return
        else:
            cls.decryption()

    @classmethod
    def create_salt(cls):
        """Creates a salt based on a random 16 digit integer and saves
        it either to a file or online, based on the initial users choice"""
        logger.debug("creating salt")

        na = int.from_bytes(os.urandom(16), byteorder="big")
        cl = str(na)
        cls.salt = cl.encode()

        if Clouded.decidingBool:
            Clouded.sheet.update_cell(1, Clouded.startpoint + 1, cls.salt.decode())
        else:
            with open("salt.txt", "wb") as st:
                st.write(cls.salt)

        logger.info("new salt created")

    @classmethod
    def encryption(cls, password, service):
        """Encrypts a given passwords and saves it with the service"""
        logger.info("encryption about to begin")

        cls.generate_fernet()
        encrypted = cls.fernet.encrypt(password.encode())
        new = (service, cls.magic_string + encrypted.decode())

        cls.jsondata.update([new])
        cls.passwordDict.update([(service, password)])
        cls.rawData.update([(service, encrypted.decode())])

        if Clouded.decidingBool:
            Clouded.heaven(service, encrypted.decode())
            Onlygui.menu()
        else:
            passwordfile = open("password_dict.json", "w")
            json.dump(cls.jsondata, passwordfile, indent=2)
            passwordfile.close()

        logger.debug("new password saved and encrypted")
        return

    @classmethod
    def decryption(cls):
        """Decrypts the dictionnary object, one a time and saves it to a new
        dictionnary object"""
        cls.passwordDict = dict(map(lambda x: (x[0], cls.fernet.decrypt(x[1].encode())), cls.rawData.items()))
        Onlygui.menu()

    @classmethod
    def general_encryption(cls, new_password):
        """Encrypts the complete password set using the new user given passsword
        and saves it either online or in a file"""
        logger.info("checking for password descriptions")

        if cls.restrictions(new_password):
            return
        else:
            pass

        cls.assword = new_password
        logger.info("starting new encryption proccess with: "+ cls.assword)
        cls.create_salt()
        cls.generate_fernet()

        cls.rawData = dict(map(lambda x: (x[0], cls.fernet.encrypt(x[1])), cls.passwordDict.items()))
        cls.jsondata = dict(map(lambda x: (x[0], cls.magic_string + x[1].decode()), cls.rawData.items()))

        if Clouded.decidingBool:
            Clouded.distort_heaven()
        else:
            save_general = open("password_dict.json", "w")
            json.dump(cls.jsondata, save_general, indent=2)
            save_general.close()

        logger.info("encryption proccess has finished with no problems")
        Onlygui.menu()

    @classmethod
    def bitty_encryption(cls, bitty):
        """Encrypts with the fernet a single string"""
        return cls.fernet.encrypt(bitty.encode())

class MainGui:
    base_font = 20
    btnfont = 15

    def __init__(self, parent):
        self.root = parent
        self.buildself()

    def buildself(self):
        user32 = ctypes.windll.user32
        screensize = user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)
        self.root.title("Cerra")
        self.root.iconbitmap("new_ico_cerra.ico")
        self.root.geometry("+"+str(round(screensize[0]/3))+"+"+str(round(screensize[1]/3)))
        self.start()

    def start(self):
        logger.info("start menu")

        button_length = 30

        try:
            self.destruction()
        except Exception:
            pass

        self.child = tk.Frame(self.root,relief="sunken")
        self.child.grid(row=0,column=0)

        msg = tk.Label(self.child,text="Choose Password Set",font=("Courier", 30))
        msg.grid(row=0,column=0,padx=50)

        onlinebtn = tk.Button(self.child,width=button_length,text="Online",command=self.online,font=(None, MainGui.btnfont))
        onlinebtn.grid(row=2,column=0,pady=5)

        offlinebtn = tk.Button(self.child,width=button_length,text="Offline",command=self.offline,font=(None, MainGui.btnfont))
        offlinebtn.grid(row=1,column=0,pady=5)

    def destruction(self):
        logger.debug("previous frame destroyed")
        self.child.destroy()
        self.child = tk.Frame(self.root, relief="sunken")
        self.child.grid(row=0,column=0)

    def hide_this(self, entrybox, bool, cbutton):
        if bool.get() == True:
            bool.set(False)
            entrybox.config(show="")
            cbutton.config(text="hide")
        else:
            bool.set(True)
            entrybox.config(show="●")
            cbutton.config(text="show")

    def switch(self, event=None):
        self.password_id.config(cursor="wait")
        self.name_id.config(cursor="wait")
        self.child.config(cursor="wait")
        Clouded.tesesame(self.name_id, self.password_id)
        try:
            self.child.config(cursor="")
            self.password_id.config(cursor="")
            self.name_id.config(cursor="")
        except:
            pass
        else:
            pass

    def online(self):
        self.destruction()

        logger.info("online password set menu")

        keepit = tk.BooleanVar()
        keepit.set(True)

        name_label = tk.Label(self.child, text="Name ID:",font=(None, MainGui.base_font))
        name_label.grid(row=0, column=0, sticky=tk.W)
        password_label = tk.Label(self.child, text="Password:",font=(None, MainGui.base_font))
        password_label.grid(row=1, column=0, sticky=tk.W)

        self.name_id = tk.Entry(self.child, width=40, font=(None, MainGui.btnfont))
        self.name_id.grid(row=0, column=1, columnspan=2, sticky=tk.W, padx=2)
        self.password_id = tk.Entry(self.child, width=30, show="●", font=(None, MainGui.btnfont))
        self.password_id.grid(row=1, column=1, sticky=tk.W)

        secure_one = tk.Button(self.child, width=5, text='show', command=lambda: self.hide_this(self.password_id, keepit, secure_one),font=(None, MainGui.btnfont))
        secure_one.grid(row=1, column=2, padx=5, sticky=tk.W)

        try_it = tk.Button(self.child, text="Request", command=self.switch, font=(None, MainGui.btnfont))
        try_it.grid(row=2, column=0, columnspan=2, pady=5, padx=132)

        returnbtn = tk.Button(self.child, text="Return", command=self.start,font=(None, MainGui.btnfont))
        returnbtn.grid(row=2, column=2)

        self.password_id.bind("<Return>", self.switch)

        Clouded(try_it)

    def offline(self):
        self.destruction()

        logger.info("offline password set menu")
        Clouded.decidingBool = False

        keepit = tk.BooleanVar()
        keepit.set(True)

        entry_label = tk.Label(self.child, text='Enter Password',font=(None, MainGui.base_font), padx=10)
        entry_label.grid(row=0, column=0, pady=10, sticky=tk.W)

        self.password_entry = tk.Entry(self.child, width=30, show='●',font=(None, MainGui.btnfont))
        self.password_entry.grid(row=1, column=0, sticky=tk.E, padx=10)
        self.password_entry.focus()

        hide = tk.Button(self.child, text='show',font=(None, MainGui.btnfont), command=lambda: self.hide_this(self.password_entry, keepit, hide))
        hide.grid(row=1, column=1, padx=10, sticky=tk.W)

        submit = tk.Button(self.child, text='submit password',font=(None, MainGui.btnfont), command=self.test_password)
        submit.grid(row=2, column=0, columnspan=2, padx=100, pady=10)

        returnbtn = tk.Button(self.child, text="Return", command=self.start,font=(None, MainGui.btnfont))
        returnbtn.grid(row=2, column=1)

        self.password_entry.bind("<Return>", self.test_password)

    def test_password(self, event=None):
        logger.info("entering password testing functional class")
        assword = self.password_entry.get()
        self.password_entry.delete(0, tk.END)
        Secretsasfuck(assword)

    def onClick(self, choice):
        if choice == "Password Catalogue":
            if not bool(Secretsasfuck.jsondata) and not Clouded.decidingBool:
                messagebox.showerror("Missing", "No Passwords Saved, Add One")
                self.add_account()
            else:
                self.password_catalogue()

        if choice == "Add Password":
            self.add_account()

        if choice == "Edit Pasword":
            self.edit()

        if choice == "Delete Password":
            self.delete_password()

        if choice == "Change Master Password":
            self.change_master()

        if choice == "Quit":
            sys.exit()

    def menu(self):
        self.destruction()

        menu_choices = ("Password Catalogue", "Add Password",
                        "Edit Pasword", "Delete Password",
                        "Change Master Password", "Quit")

        for title in menu_choices:
            menu_button = tk.Button(self.child, width=30, text=title, font=(None,MainGui.btnfont), command=lambda title=title: self.onClick(title))
            menu_button.grid(row=menu_choices.index(title),column=0, padx=10,pady=5)

    def clicked(self, event):
        self.my_label.delete(0, tk.END)
        self.my_label.insert(0, Secretsasfuck.passwordDict[self.listbox.get(tk.ACTIVE)])
        self.serviceinfo = self.listbox.get(tk.ACTIVE)

    def password_catalogue(self):
        logger.info("creating password catalogue")
        self.destruction()

        frame = tk.LabelFrame(self.child, bd=1, text='your accounts', padx=50, pady=10)
        frame.grid(row=0, column=0, padx=10, pady=10)

        scrollbar = tk.Scrollbar(frame)
        scrollbar.grid(row=2, column=1)

        self.listbox = tk.Listbox(frame, yscrollcommand=scrollbar.set)
        self.listbox.grid(row=2, column=0)

        self.my_label = tk.Entry(self.child, width=25, show="●", font=(None, MainGui.base_font))
        self.my_label.insert(0, '')
        self.my_label.grid(row=0, column=1, columnspan=2, padx=20, pady=10)


        pizza = tk.StringVar()
        pizza.set('perperoni')
        keepit = tk.BooleanVar()
        keepit.set(True)

        for key in Secretsasfuck.passwordDict:
                self.listbox.insert(tk.END, key)

        scrollbar.config(command=self.listbox.yview)
        self.listbox.bind("<Double-Button-1>", self.clicked)

        return_to_menu = tk.Button(self.child, text='return to menu', command=self.menu, font=(None, MainGui.btnfont))
        return_to_menu.grid(row=1, column=0, pady=10)

        copytcb = tk.Button(self.child, text="Copy To Clipboard", command=lambda: pyperclip.copy(self.my_label.get()), font=(None, MainGui.btnfont))
        copytcb.grid(row=1, column=1)

        hidebtn = tk.Button(self.child, text="show", command=lambda: self.hide_this(self.my_label, keepit, hidebtn), font=(None, MainGui.btnfont))
        hidebtn.grid(row=1, column=2)

    def assign_it(self):

        if not self.entry_account.get() or not self.entry_password.get():
            messagebox.showinfo("...", "Entries cannot be empty")
            return

        Secretsasfuck.encryption(self.entry_password.get(), self.entry_account.get())
        self.menu()

    def add_account(self):
        self.destruction()
        logger.info("creating account adder window")

        trouble = tk.BooleanVar()
        trouble.set(True)
        modes = []

        instructions = tk.Label(self.child, text='Enter service and password', font=(None, MainGui.base_font))
        instructions.grid(row=0, column=0, columnspan=2, padx=50)

        self.entry_account = tk.Entry(self.child, width=35, font=(None, MainGui.btnfont))
        self.entry_account.grid(row=1, column=0, columnspan=2, pady=20, padx=30, sticky=tk.W)

        self.entry_password = tk.Entry(self.child, width=30, font=(None, MainGui.btnfont), show="●")
        self.entry_password.grid(row=2, column=0, columnspan=2, pady=20, padx=30, sticky=tk.W)

        confirm_button = tk.Button(self.child, width=10, text='Enter', command=self.assign_it, font=(None, MainGui.btnfont))
        confirm_button.grid(row=3, column=0, padx=2, sticky=tk.W)

        secure_one = tk.Button(self.child, width=5, text='show', command=lambda: self.hide_this(self.entry_password, trouble, secure_one),font=(None, MainGui.btnfont))
        secure_one.grid(row=2, column=1, padx=2, sticky=tk.E)

        return_to_menu = tk.Button(self.child, text='return to menu', command=self.menu, font=(None, MainGui.btnfont))
        return_to_menu.grid(row=3, column=1, columnspan=2, padx=10, pady=10, sticky=tk.E)

    def edit_action(self):
        if Clouded.decidingBool:
            neuer = Secretsasfuck.bitty_encryption(self.my_label.get())
            Clouded.change_heaven(Secretsasfuck.rawData[self.serviceinfo], neuer.decode())
            Secretsasfuck.rawData.update([(self.serviceinfo, neuer)])
            Secretsasfuck.passwordDict.update([(self.serviceinfo, self.my_label.get())])
        else:
            Secretsasfuck.encryption(self.my_label.get(), self.serviceinfo)
        self.menu()

    def edit(self):
        logger.info("creating password edit window")
        self.serviceinfo = None

        self.destruction()

        frame = tk.LabelFrame(self.child, bd=1, text='your accounts', padx=50, pady=10)
        frame.grid(row=0, column=0, rowspan=2, padx=10, pady=10)

        scrollbar = tk.Scrollbar(frame)
        scrollbar.grid(row=2, column=1)

        self.listbox = tk.Listbox(frame, yscrollcommand=scrollbar.set)
        self.listbox.grid(row=2, column=0)

        self.my_label = tk.Entry(self.child, width=25, show="●", font=(None, MainGui.base_font))
        self.my_label.insert(0, '')
        self.my_label.grid(row=1, column=1, columnspan=2, padx=20)

        keepit = tk.BooleanVar()
        keepit.set(True)

        for key in Secretsasfuck.passwordDict:
                self.listbox.insert(tk.END, key)

        scrollbar.config(command=self.listbox.yview)
        self.listbox.bind("<Double-Button-1>", self.clicked)

        self.warninglabel = tk.Label(self.child, text="Change The Password", fg="red", font=(None, MainGui.base_font))
        self.warninglabel.grid(row=0, column=1)

        return_to_menu = tk.Button(self.child, text='return to menu', command=self.menu, font=(None, MainGui.btnfont))
        return_to_menu.grid(row=2, column=0, pady=10)

        copytcb = tk.Button(self.child, text="Submit Changes", command=self.edit_action, font=(None, MainGui.btnfont))
        copytcb.grid(row=2, column=1)

        hidebtn = tk.Button(self.child, text="show", command=lambda: self.hide_this(self.my_label, keepit, hidebtn), font=(None, MainGui.btnfont))
        hidebtn.grid(row=2, column=2)

    def delete_password_action(self):
        MsgBox = tk.messagebox.askquestion('Delete','Are you sure you want to delete ' + self.serviceinfo + "'s password",icon = 'warning')

        if MsgBox == "yes":
            del Secretsasfuck.rawData[self.serviceinfo]
            del Secretsasfuck.passwordDict[self.serviceinfo]

            if Clouded.decidingBool:
                Clouded.hell(Secretsasfuck.rawData)
            else:
                del Secretsasfuck.jsondata[self.serviceinfo]
                smaller = open("password_dict.json", "w")
                json.dump(Secretsasfuck.jsondata, smaller, indent=2)
                smaller.close()
            self.menu()
        else:
            return

    def delete_password(self):
        logger.info("creating delete password info")

        self.serviceinfo = None

        self.destruction()

        frame = tk.LabelFrame(self.child, bd=1, text='your accounts', padx=50, pady=10)
        frame.grid(row=0, column=0, rowspan=2, padx=10, pady=10)

        scrollbar = tk.Scrollbar(frame)
        scrollbar.grid(row=2, column=1)

        self.listbox = tk.Listbox(frame, yscrollcommand=scrollbar.set)
        self.listbox.grid(row=2, column=0)

        self.my_label = tk.Entry(self.child, width=25, show="●", font=(None, MainGui.base_font))
        self.my_label.insert(0, '')
        self.my_label.grid(row=1, column=1, columnspan=2, padx=20)

        keepit = tk.BooleanVar()
        keepit.set(True)

        for key in Secretsasfuck.passwordDict:
                self.listbox.insert(tk.END, key)

        scrollbar.config(command=self.listbox.yview)
        self.listbox.bind("<Double-Button-1>", self.clicked)

        self.warninglabel = tk.Label(self.child, text="Delete Password", fg="red", font=(None, MainGui.base_font))
        self.warninglabel.grid(row=0, column=1)

        return_to_menu = tk.Button(self.child, text='return to menu', command=self.menu, font=(None, MainGui.btnfont))
        return_to_menu.grid(row=2, column=0, pady=10)

        deletebtn = tk.Button(self.child, text="Delete", bg="red", command=self.delete_password_action, font=(None, MainGui.btnfont))
        deletebtn.grid(row=2, column=1)

        hidebtn = tk.Button(self.child, text="show", command=lambda: self.hide_this(self.my_label, keepit, hidebtn), font=(None, MainGui.btnfont))
        hidebtn.grid(row=2, column=2)

    def change_master(self):
        self.destruction()

        logger.info("creating master password changer window")

        mainlbl = tk.Label(self.child, text='create password \n 8 caracters or more', font=(None, MainGui.base_font))
        mainlbl.grid(row=0, column=0, padx=100)

        master_p = tk.Entry(self.child, width=30, font=(None, MainGui.btnfont))
        master_p.grid(row=1, column=0, padx=10, pady=20)

        changebtn = tk.Button(self.child, text='Change It', command=lambda: Secretsasfuck.general_encryption(master_p.get()), font=(None, MainGui.btnfont))
        changebtn.grid(row=2, column=0)

        returnbtn = tk.Button(self.child, text='return to menu', command=self.menu, font=(None, MainGui.btnfont))
        returnbtn.grid(row=3, column=0, padx=2, pady=2, sticky=tk.W)

def main():
    global Onlygui
    root = tk.Tk()
    root.resizable(False, False)
    Onlygui = MainGui(root)
    root.mainloop()

if __name__ == "__main__":
    main()
