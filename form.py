import tkinter as tk
from tkinter import filedialog, ttk
from ttkthemes import ThemedStyle
from ECC import ECC
 
#GUI interface for ECC encryption and decryption

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Text Encryption and Decryption")
        self.style = ThemedStyle(self)
        self.style.set_theme("equilux")
        self.geometry("400x350")
        self.file_path = None
        self.selected_option = tk.StringVar()

        self.modulus = 121
        self.a = 80 #110
        self.b = 50 #69

        self.Alice = ECC(self.modulus, self.a, self.b)
        self.Bob = ECC(self.modulus, self.a, self.b)

        self.Alice.setPrivateKey(5)
        self.Bob.setPrivateKey(13)
        self.Bob.setGeneratorP(self.Alice.generator_P)
        #icon 
        self.iconbitmap('C:/school/ECC_demo-main/images_and_icons/crypt.ico')
        
        # Label for curve
        #self.curve_label = ttk.Label(self, text="Curve: y^2 = x^3 + {}x + {}".format(self.a, self.b))
        #self.curve_label.pack(pady=10)

        # Radio buttons
        self.option_frame = ttk.Frame(self)
        self.option_frame.pack(pady=10)
        self.option_label = ttk.Label(self.option_frame, text="Who is using the software:")
        self.option_label.pack(side="left")
        self.option1_button = ttk.Radiobutton(self.option_frame, text="Alice", variable=self.selected_option, value="alice")
        self.option1_button.pack(side="left")
        self.option2_button = ttk.Radiobutton(self.option_frame, text="Bob", variable=self.selected_option, value="bob")
        self.option2_button.pack(side="left")
        self.selected_option.set("Alice")

        # Text bar
        self.text_bar = tk.Text(self, height=10, width=40, font=("Calibri", 11), foreground="white")
        self.text_bar.pack(pady=10)
        self.text_bar.configure(background="black")

        # Load file button
        self.load_file_button = ttk.Button(self, text="Load file", command=self.load_file)
        self.load_file_button.pack(side="left", padx=5)

        # Save file button
        self.save_file_button = ttk.Button(self, text="Save to file", command=self.save_file)
        self.save_file_button.pack(side="left", padx=5)

        # Encryption and Decryption buttons
        self.encrypt_button = ttk.Button(self, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack(side="right", padx=5)
        self.decrypt_button = ttk.Button(self, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack(side="right", padx=5)

    def load_file(self):
        initialdir= "C:\school\ECC_demo-main\\"

        selected = self.selected_option.get()
        self.file_path = filedialog.askopenfilename(initialdir=initialdir+selected, title="Select a file", filetypes=(("Text files", "*.txt"),))
        if self.file_path:
            with open(self.file_path, "r") as file:
                file_content = file.read()
                self.text_bar.delete("1.0", "end")
                self.text_bar.insert("end", file_content)

    def save_file(self):
        initialdir= ""
        selected = self.selected_option.get()

        if selected == 'alice':
            initialdir = "C:\school\ECC_demo-main\\bob"
        else:
            initialdir = "C:\school\ECC_demo-main\\alice"
        self.file_path = "C:\school\ECC_demo-main"
        if self.file_path is not None:
            new_file_path = filedialog.asksaveasfilename(initialdir=initialdir, title="Save File", filetypes=(("Text files", "*.txt"),), defaultextension=".txt")
            if new_file_path:
                with open(new_file_path, "w") as file:
                    file.write(self.text_bar.get("1.0", "end-1c"))
                    print(f"File saved as {new_file_path}")
        else:
            print("No file loaded.")

    def encrypt(self):
        message_to_encrypt = self.text_bar.get("1.0",'end')
        self.text_bar.delete("1.0", "end")
        selected = self.selected_option.get()
        encrypted_message = ""
        if selected == "alice":
            encrypted_message = self.Alice.encrypt_string_message(message_to_encrypt, self.Bob.public_Q)
        else:
            encrypted_message = self.Bob.encrypt_string_message(message_to_encrypt, self.Alice.public_Q)
        self.text_bar.insert("end", encrypted_message)
        
    def decrypt(self):
        message_to_decrypt = self.text_bar.get("1.0",'end')
        self.text_bar.delete("1.0", "end")
        selected = self.selected_option.get()
        decrypted_message = ""
        if selected == "alice":
            decrypted_message = self.Alice.decrypt_string_message(message_to_decrypt)
        else:
            decrypted_message = self.Bob.decrypt_string_message(message_to_decrypt)
        self.text_bar.insert("end", decrypted_message)


if __name__ == "__main__":
    app = App()
    app.mainloop()





