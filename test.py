from ECC import ECC

modulus = 121
a = 110
b = 69

Alice = ECC(modulus, a, b)
Bob = ECC(modulus, a, b)

curve_name = 'y^2 = x^3 + ' + str(a) + '*x + ' + str(b) 
print('number of points on ', curve_name,' on a field F', modulus, ' is: ', len(Alice.pts))

Alice.setPrivateKey(5)
Bob.setPrivateKey(13)
Bob.setGeneratorP(Alice.generator_P)


# select a random point from the curve
message = Alice.pts[3]

# encrypt and decrypt
C1, C2 = Alice.encrypt(message, Bob.public_Q)
decrypted_message = Bob.decrypt(C1, C2)

print('original message:  ', message)
print('decrypted message: ',decrypted_message)
