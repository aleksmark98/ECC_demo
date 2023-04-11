import numpy as np
import galois
import random
import string 

# Elliptic Curve Cryptograpy
# creates a curve over a galois field
# can encrypt and decrypt a point on a curve
# elliptic curve is in form: y^2 = x^3 + a*x +  b
class ECC:

    def __init__(self, field_modulus, a, b):

        self.GF = galois.GF(field_modulus)
        if (self.GF.characteristic <= 3):
            # for characteristic 2 different equations for the point algebra is used
            # see wiki for 'Elliptic curves over a general field'
            print('choose a field modulus larger than 3')
            return

        self.a = self.GF(a % field_modulus)
        self.b = self.GF(b % field_modulus)

        if (self.isSingular(a, b)):
            print('selected curve is singular')
            return

        self.pts = self.GF([[0, 0]])

        x = self.GF(np.arange(1, field_modulus))
        x2 = x**2
        # calculate all curve points
        for i in x:
            y2 = i**3 + self.GF(a)*i + self.GF(b)
            indices = np.argwhere(x2 == y2) + 1 # x starts from 1, need to shift indices to match coords
            temp = np.full((len(indices), 2), i)
            temp[:, 1] = np.transpose(indices)
            self.pts = np.concatenate((self.pts, temp), 0)


        # generator point for public keys Q = k*P
        # Is considered to be a part of public key or even a part of curve definition.
        # In practice P should be carefully considered, as for different curves each
        # generator point can generate the whole EC point group or only a subgroup.
        # If size of the generated subgroup determines cryptographic security.
        # Here it will be selected at random.
        self.generator_P = self.pts[random.randint(0, len(self.pts)-1)]

        # private key
        self.private_k = random.randint(1, 9999) # upper bound is an arbitrary number, higher -> more secure

        # public key
        self.public_Q = self.scalarMult(self.generator_P, self.private_k)

    # checks that the curve has no cusps and self-intersections
    def isSingular(self, a, b):
        return (4*a**3 + 27*b**2) == 0

    # addition on eliptical curves

    # multiplies a point pt by a scalar c
    def scalarMult(self, pt, c):
        c = c % self.GF.order
        if (c == 0):
            return self.GF([0, 0])
        if (c == 1):
            return pt

        mults = int(np.log2(c))  # multiply itself mults-1 times
        adds = c - 2**mults

        ans = self.addPts(pt, pt)
        stopCount = 2
        while (stopCount < mults):
            ans = self.addPts(ans, ans)
            stopCount = stopCount+1

        stopCount = 0
        while (stopCount < adds):
            ans = self.addPts(ans, pt)
            stopCount = stopCount+1

        return ans

    # addition on eliptical curves
    def addPts(self, P, Q):
        ans = self.GF([0, 0])

        if (any(P != Q)):
            if (Q[0] == P[0]):
                return ans
            if (all(P == ans)):
                return Q
            if (all(Q == ans)):
                return P

            ans[0] = ( (Q[1] - P[1]) / (Q[0] - P[0]) )**2 - P[0] - Q[0]
            ans[1] = ( (Q[1] - P[1]) / (Q[0] - P[0]) ) * (P[0] - ans[0]) - P[1]
        else:
           if (all(P == ans)):
               return ans
           
           #ans[0] = ( (self.GF(3)* P[0]**2 + self.a) / (self.GF(2)* P[1]) )**2                - self.GF(2)* P[0]
           #ans[1] = ( (self.GF(3)* P[0]**2 + self.a) / (self.GF(2)* P[1]) ) * (P[0] - ans[0]) - P[1]

           # TEMP debugging: catch a division by zero (shouldn't occur)
           try:
               ans[0] = ( (self.GF(3)* P[0]**2 + self.a) / (self.GF(2)* P[1]) )**2                - self.GF(2)* P[0]
               ans[1] = ( (self.GF(3)* P[0]**2 + self.a) / (self.GF(2)* P[1]) ) * (P[0] - ans[0]) - P[1]
           except:
               print('ans ', ans)
               print('P ', P)
               print('divisor ', self.GF(2)* P[1])

        # TEMP debugging: occasionaly the result of point addition is outside the EC group
        if not (ans.tolist() in self.pts.tolist()):
            print('P ', P)
            print('Q ', Q)
            print('ans ', ans)

        return ans
    
    def setPrivateKey(self, k):
        self.private_k = k
        self.public_Q = self.scalarMult(self.generator_P, self.private_k)

    def setGeneratorP(self, point):
        if (point.tolist() in self.pts.tolist()):
            self.generator_P = point
            self.public_Q = self.scalarMult(self.generator_P, self.private_k)
        else:
            print('error, point not on curve')

   # set generator point by index of the point
   # def setGeneratorP(self, ptsIndex):
   #     self.generator_P = self.pts[ ptsIndex % len(self.pts) ]
   #     self.public_Q = self.scalarMult(self.generator_P, self.private_k)

    def encrypt(self, point, publicKeyQ):
        scalar = random.randint(1, self.GF.order-1)
        C1 = self.scalarMult(self.generator_P, scalar)
        C2 = self.addPts(point, self.scalarMult(publicKeyQ, scalar))
        
        return C1, C2

    def decrypt(self, C1, C2):
        C1 = self.scalarMult(C1, self.private_k)
        C1[1] = -C1[1]

        return self.addPts(C2, C1)
    
    def encrypt_char(self, char_message, publicKeyQ):
        """
        Encrypts a single character message using the provided public key.

        :param char_message: The character message to encrypt.
        :param publicKeyQ: The public key to use for encryption.
        :return: A tuple of the indices of points representing encrypted character in the pts list.
        """
        printable_characters = string.printable
        char_ord = printable_characters.index(char_message)
        used_point = self.pts[char_ord]
        C1, C2 = self.encrypt(used_point, publicKeyQ)
        index1 = (self.pts.tolist()).index(C1.tolist())
        index2 = (self.pts.tolist()).index(C2.tolist())

        return (index1, index2)
    
    def decrypt_char(self, char_ord1, char_ord2):
        """
        Decrypts a single character message using the provided indices of curve points.

        :param char_ord1: The index of the first point in the pts list.
        :param char_ord2: The index of the second point in the pts list.
        :return: The decrypted character.
        """
        printable_characters = string.printable
        C1, C2 = self.pts[char_ord1], self.pts[char_ord2]
        decrypted_point = self.decrypt(C1, C2)
        
        return printable_characters[self.pts.tolist().index(decrypted_point.tolist())]

        
    def encrypt_string_message(self, message, publicKeQ):
        """
        Encrypts a string message using the provided public key.

        :param message: The string message to encrypt.
        :param publicKeQ: The public key to use for encryption.
        :return: The encrypted string message.
        """
        encrypted_string = ""
        for i in range(len(message)):
            encrypted_chars = self.encrypt_char(message[i], publicKeQ)
            encrypted_string += str(encrypted_chars[0]) + ' ' + str(encrypted_chars[1]) + ' '
        
        return encrypted_string

    def decrypt_string_message(self, message):
        """
        Decrypts a string message using the provided printable characters and points.

        :param message: The encrypted string message.
        :return: The decrypted string message.
        """

        decrypted_string = ""
        message = message.split()
        for i in range(len(message)//2):
            decrypted_string += self.decrypt_char(int(message[2*i]), int(message[2*i+1]))
            
        return decrypted_string
