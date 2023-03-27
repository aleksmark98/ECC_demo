import numpy as np
import galois
import random


# Elliptic Curve Cryptograpy
# creates a curve over a galois field
# can encrypt and decrypt a point on a curve
# elliptic curve is in form: y^2 = x^3 + a*x + b
class ECC:

    def __init__(self, field_modulus, a, b):

        self.GF = galois.GF(field_modulus)
        if (self.GF.characteristic <= 3):
            # for characteristic 2 different equations for the point algebra is used
            # see wiki for 'Elliptic curves over a general field'
            print('choose a field modulus larger than 3')
            return

        a = a % field_modulus
        b = b % field_modulus
        self.a = a
        self.b = b

        if (self.isSingular(a,b)):
            print('selected curve is singular')
            return

        self.pts = self.GF([[0, 0]])

        x = self.GF(np.arange(1, field_modulus))
        x
        x2 = x**2
        # calculate all curve points
        for i in x:
            y2 = i**3 + self.GF(a)*i + self.GF(b)
            indices = np.argwhere(x2 == y2)
            indices = indices + 1 # x starts from 1, need to shift indices to match coords
            temp = np.full( (len(indices), 2), i)
            temp[:,1] = np.transpose(indices)
            self.pts = np.concatenate((self.pts, temp),0)

        # generator point for public keys Q = k*P
        # Is considered to be a part of public key or even a part of curve definition.
        # In practice P should be carefully considered, as for different curves each
        # generator point can generate the whole EC point group or only a subgroup.
        # If size of the generated subgroup determines cryptographic security.
        # Here it will be selected at random.
        self.generator_P = self.pts[ random.randint(0,len(self.pts)-1) ]

        # private key
        self.private_k = random.randint(1,9999)

        # public key
        self.public_Q = self.scalarMult(self.generator_P, self.private_k)

    # checks that the curve has no cusps and self-intersections
    def isSingular(self, a, b):
	    return (4*a**3 + 27*b**2) == 0

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

           ans[0] = ( (3* P[0]**2 + self.GF(self.a)) / (2*P[1]) )**2 - 2*P[0]
           ans[1] = ( (3* P[0]**2 + self.GF(self.a)) / (2*P[1]) ) * (P[0] - ans[0]) - P[1]

        return ans

    # multiplies a point pt by a scalar c
    def scalarMult(self, pt, c):
        c = c % self.GF.order
        if (c == 0):
            return self.GF([0, 0])
        if (c == 1):
            return pt

        mults = int(np.log2(c)) # multiply itself mults-1 times
        adds = c - 2**mults

        ans = self.addPts(pt,pt)
        stopCount = 2
        while (stopCount < mults):
            ans = self.addPts(ans,ans)
            stopCount = stopCount+1

        stopCount = 0
        while (stopCount < adds):
            ans = self.addPts(ans,pt)
            stopCount = stopCount+1
        
        return ans

    def setPrivateKey(self, k):
        self.private_k = k
        self.public_Q = self.scalarMult(self.generator_P, self.private_k)

    def setGeneratorP(self, point):
        if(point.tolist() in self.pts.tolist()):
            self.generator_P = point
            self.public_Q = self.scalarMult(self.generator_P, self.private_k)
        else:
            print('error, point not on curve')

   # set generator point by index of the point
   # def setGeneratorP(self, ptsIndex):
   #     self.generator_P = self.pts[ ptsIndex % len(self.pts) ]
   #     self.public_Q = self.scalarMult(self.generator_P, self.private_k)

    def encrypt(self, point, publicKeyQ):
        scalar = random.randint(1,self.GF.order-1)
        C1 = self.scalarMult(self.generator_P, scalar)
        C2 = self.addPts(point, self.scalarMult(publicKeyQ, scalar))
        return C1, C2

    def decrypt(self, C1, C2):
        # M = C2 - k*C1
        C1 = self.scalarMult(C1,self.private_k)
        C1[1] = -C1[1]
        return self.addPts(C2, C1)
