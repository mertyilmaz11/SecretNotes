from tkinter import *
from tkinter import messagebox
from PIL import ImageTk,Image
import base64

FONT = ["Arial",10,"normal"]

window = Tk()
window.title("Secret Notes")
window.config(padx=10,pady=10)

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encrypt():
    title = title_entry.get()
    message = text_entry.get(1.0,END)
    master_key = masterkey_entry.get()
    if title == "" or message == "" or master_key == "":
        messagebox.showerror(title="Error!",message="Please enter all information")
    else:
        message_encrypted = encode(master_key,message)
        try:
            with open("mysecret.txt", mode="a") as secretfile:
                secretfile.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("mysecret.txt",mode="w") as secretfile:
                secretfile.write(f"\n{title}\n{message_encrypted}")
        finally:
            title_entry.delete(0,END)
            text_entry.delete(1.0,END)
            masterkey_entry.delete(0,END)

def decrypt():
    message_encrypted = text_entry.get(1.0,END)
    master_key = masterkey_entry.get()
    if message_encrypted == "" or master_key == "":
        messagebox.showerror(title="Error!",message="Please enter all information")
    else:
        try:
            message_decrypted = decode(master_key,message_encrypted)
            text_entry.delete(1.0,END)
            text_entry.insert(1.0,message_decrypted)
        except:
            messagebox.showerror(title="Error!",message="Please make sure encrypt info")


img = ImageTk.PhotoImage(Image.open("secretnoteslogo.png"))
logo = Label(image=img)
logo.pack()

title_label = Label(text="Enter your title")
title_label.pack()

title_entry = Entry(width=30)
title_entry.pack()

text_label = Label(text="Enter your secret")
text_label.pack()

text_entry = Text(width=30,height=15)
text_entry.pack()

masterkey_label = Label(text="Enter master key")
masterkey_label.pack()

masterkey_entry = Entry(width=30)
masterkey_entry.pack()

save_button = Button(text="Save & Encrypt",command=save_and_encrypt)
save_button.pack()

decrypt_button = Button(text="Decrypt",command=decrypt)
decrypt_button.pack()

window.mainloop()