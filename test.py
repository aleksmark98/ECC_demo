from ECC import ECC
import string

modulus = 121
a = 80  # 110
b = 50  # 69

Alice = ECC(modulus, a, b)
Bob = ECC(modulus, a, b)

curve_name = 'y^2 = x^3 + ' + str(a) + '*x + ' + str(b) 
print('number of points on ', curve_name,' on a field F', modulus, ' is: ', len(Alice.pts))

Alice.setPrivateKey(5)
Bob.setPrivateKey(13)
Bob.setGeneratorP(Alice.generator_P)


# select a random point from the curve
message = Alice.pts[5]

#encrypt and decrypt
C1, C2 = Alice.encrypt(message, Bob.public_Q)
decrypted_message = Bob.decrypt(C1, C2)
for point in Alice.pts:
    message = point
    # encrypt and decrypt
    C1, C2 = Alice.encrypt(message, Bob.public_Q)
    decrypted_message = Bob.decrypt(C1, C2)
    print('original message:  ', message)
    print(C1, C2)
    print("is C1 in pts", C1 in Alice.pts)
    print("is C2 in pts", C2 in Alice.pts)
    print('decrypted message: ',decrypted_message)




string_message = "ahoj, jsem jindra, potrebuji pomoc, posli jednotky"
encrypted_string = Alice.encrypt_string_message(string_message, Bob.public_Q)


with open("encrypted_text.txt", "w") as f:
    f.write(encrypted_string)
    f.close()

with open('encrypted_text.txt', 'r') as file:
    encrypted_string2 = file.read()

print("encrypted_string2", encrypted_string2)
decrypted_string = Bob.decrypt_string_message(encrypted_string2)
print(decrypted_string)