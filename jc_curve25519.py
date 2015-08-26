
""" 
 By David Oswald, d.f.oswald@cs.bham.ac.uk
 26 August 2015
 
 Some of this code is based on information or code from
 
 - Sam Kerr: http://samuelkerr.com/?p=431 
 - Eli Bendersky: http://eli.thegreenplace.net/2009/03/07/computing-modular-square-roots-in-python/ 
 - http://cr.yp.to/highspeed/naclcrypto-20090310.pdf, page 7
 
 The code of Eli is in the public domain:
 "Some of the blog posts contain code; unless otherwise stated, all of it is 
 in the public domain"
 
 =======================================================================
 
 This is free and unencumbered software released into the public domain.
 
 Anyone is free to copy, modify, publish, use, compile, sell, or
 distribute this software, either in source code form or as a compiled
 binary, for any purpose, commercial or non-commercial, and by any
 means.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.
 
 =======================================================================
 
 If this software is useful to you, I'd appreciate an attribution,
 contribution (e.g. bug fixes, improvements, ...), or a beer.
"""

from smartcard.Exceptions import NoCardException
from smartcard.System import *
from smartcard.util import toHexString
from struct import *

class JCCurve25519:
    
    # Montgomery parameters of Curve25519
    p = pow(2,255) - 19
    a_m = 486662 
    b_m = 1
    r = pow(2, 252) + 27742317777372353535851937790883648493
    
    # Precomputed Weierstrass parameters of Curve25510
    a_w = 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144L
    b_w = 0x7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864L
    Gx_w = 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245aL
    Gy_w = 0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9L

    @staticmethod
    def modular_sqrt(a, p):
        """ Find a quadratic residue (mod p) of 'a'. p
            must be an odd prime.
    
            Solve the congruence of the form:
                x^2 = a (mod p)
            And returns x. Note that p - x is also a root.
    
            0 is returned is no square root exists for
            these a and p.
    
            The Tonelli-Shanks algorithm is used (except
            for some simple cases in which the solution
            is known from an identity). This algorithm
            runs in polynomial time (unless the
            generalized Riemann hypothesis is false).
        """
        # Simple cases
        #
        if JCCurve25519.legendre_symbol(a, p) != 1:
            return 0
        elif a == 0:
            return 0
        elif p == 2:
            return p
        elif p % 4 == 3:
            return pow(a, (p + 1) / 4, p)
    
        # Partition p-1 to s * 2^e for an odd s (i.e.
        # reduce all the powers of 2 from p-1)
        #
        s = p - 1
        e = 0
        while s % 2 == 0:
            s /= 2
            e += 1
    
        # Find some 'n' with a legendre symbol n|p = -1.
        # Shouldn't take long.
        #
        n = 2
        while JCCurve25519.legendre_symbol(n, p) != -1:
            n += 1
    
        # Here be dragons!
        # Read the paper "Square roots from 1; 24, 51,
        # 10 to Dan Shanks" by Ezra Brown for more
        # information
        #
    
        # x is a guess of the square root that gets better
        # with each iteration.
        # b is the "fudge factor" - by how much we're off
        # with the guess. The invariant x^2 = ab (mod p)gx_w = (9 + a_m/3)%p
        # is maintained throughout the loop.
        # g is used for successive powers of n to update
        # both a and b
        # r is the exponent - decreases with each update
        #
        x = pow(a, (s + 1) / 2, p)
        b = pow(a, s, p)
        g = pow(n, s, p)
        r = e
    
        while True:
            t = b
            m = 0
            for m in xrange(r):
                if t == 1:
                    break
                t = pow(t, 2, p)
    
            if m == 0:
                return x
    
            gs = pow(g, 2 ** (r - m - 1), p)
            g = (gs * gs) % p
            x = (x * gs) % p
            b = (b * g) % p
            r = m
    
    @staticmethod
    def legendre_symbol(a, q):
        """ Compute the Legendre symbol a|p using
            Euler's criterion. p is a prime, a is
            relatively prime to p (if p divides
            a, then a|p = 0)
    
            Returns 1 if a has a square root modulo
            p, -1 otherwise.
        """
        ls = pow(a, (q - 1) / 2, q)
        return -1 if ls == q - 1 else ls
    
    @staticmethod
    def weierstrass_to_montgomery(xW):
        xM = (((JCCurve25519.b_m * xW) % JCCurve25519.p) - JCCurve25519.a_m * JCCurve25519.inv(3)) % JCCurve25519.p
        return xM

    @staticmethod
    def montgomery_to_weierstrass(xp):
        xp = (xp + JCCurve25519.a_m * JCCurve25519.inv(3)) % JCCurve25519.p 
        yp2 = (((pow(xp,3) % JCCurve25519.p) + JCCurve25519.a_w*xp) % JCCurve25519.p + JCCurve25519.b_w) % JCCurve25519.p
        yp = JCCurve25519.modular_sqrt(yp2, JCCurve25519.p)
        return [xp, yp]
    

    @staticmethod
    def unpack_le(s):
        if len(s) != 32:
            raise Exception("Length != 32")

        return sum((s[i]) << (8 * i) for i in range(32))

    @staticmethod
    def pack_le(n):
        r = []

        for i in range(32):
            r.append(int((n >> (8 * i)) & 0xff))

        return r
        
    @staticmethod    
    def unpack_be(s):
        if len(s) != 32:
            raise Exception("Length != 32")
            
        return sum((s[i]) << (8 * (31-i)) for i in range(32))
    
    @staticmethod
    def pack_be(n):
        r = []
        
        for i in range(32):
            r.append(int((n >> (8 * (31-i))) & 0xff))
            
        return r
    
    # The follwing code is based on 
    # http://cr.yp.to/highspeed/naclcrypto-20090310.pdf, page 7
    
    @staticmethod    
    def clamp(n):
        n &= ~7
        n &= ~(128 << 8 * 31)
        n |= 64 << 8 * 31
        return n
    
    @staticmethod 
    def expmod(b, e, m):
        if e == 0: 
            return 1
        t = JCCurve25519.expmod(b, e / 2, m) ** 2 % m
        if e & 1: 
            t = (t * b) % m
        return t
    
    @staticmethod 
    def inv(x):
        return JCCurve25519.expmod(x, JCCurve25519.p - 2, JCCurve25519.p)
        
    # Addition and doubling formulas taken
    # from Appendix D of "Curve25519:
    # new Diffie-Hellman speed records".
    @staticmethod 
    def add((xn,zn), (xm,zm), (xd,zd)):
        x = 4 * (xm * xn - zm * zn) ** 2 * zd
        z = 4 * (xm * zn - zm * xn) ** 2 * xd
        return (x % JCCurve25519.p, z % JCCurve25519.p)
        
    @staticmethod    
    def double((xn,zn)):
        x = (xn ** 2 - zn ** 2) ** 2
        z = 4 * xn * zn * (xn ** 2 + JCCurve25519.a_m * xn * zn + zn ** 2)
        return (x % JCCurve25519.p, z % JCCurve25519.p)
    
    @staticmethod 
    def smul(s, base):
        one = (base,1)
        two = JCCurve25519.double(one)
        # f(m) evaluates to a tuple
        # containing the mth multiple and the
        # (m+1)th multiple of base.
        def f(m):
            if m == 1: return (one, two)
            (pm, pm1) = f(m / 2)
            if (m & 1):
                return (JCCurve25519.add(pm, pm1, one), JCCurve25519.double(pm1))
            return (JCCurve25519.double(pm), JCCurve25519.add(pm, pm1, one))
        
        ((x,z), _) = f(s)
        
        return (x * JCCurve25519.inv(z)) % JCCurve25519.p

    def __init__(self):
        self.connected = False
   
    def isConnected(self):
        return self.connected
         
    def connect(self):
        print "== Available readers:"
        
        self.connected = False
        
        rl = smartcard.System.readers()
        i = 0
        for r in rl:
            print str(i) + ") " + r.name
            i = i + 1
            
        if len(rl) == 0:
            raise Exception("No readers available")
            
        
        print " Connecting to first reader ... "
        
        try:
            self.c = r.createConnection()
            self.c.connect()
            print " ATR: " + toHexString(self.c.getATR())
        except Exception:
            raise Exception("Communication error")
    
        # select app
        SELECT = [0x00, 0xA4, 0x04, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        
        response, sw1, sw2 = self.c.transmit(SELECT)
    
        if sw1 == 0x90 and sw2 == 0x00:
            print " App selected"
            self.connected = True
        else:
            raise Exception("App select failed")
            
    def generateKeypair(self):
        """ Generates a key pair on card for debug purposes, will
            return public and private key
            This method handles the conversion to Montgomery coordinates etc.
        """
        if self.connected == False:
            raise Exception("Not connected")
        
        # Generate key APDU
        GENKEY = [0x00, 0x01, 0x0, 0x00, 0x00]
        
        response, sw1, sw2 = self.c.transmit(GENKEY)
    
        if sw1 != 0x90 or sw2 != 0x00:
            raise Exception("Card error")
            return False
            
        if len(response) != 64:
            raise Exception("Response is " + str(len(response)) + " byte")
        
        # Unpack and convert internally
        skW = JCCurve25519.unpack_be(response[0:32])
        pkW = JCCurve25519.unpack_be(response[32:64])
        
        # print "skW = " + hex(skW)
        # print "pkW = " + hex(pkW)
        
        # convert to Curve25519 standards
        sk = skW << 3
        pk = JCCurve25519.weierstrass_to_montgomery(pkW)
        
        # Multiply PK by 8 (three doublings)
        pk = JCCurve25519.smul(8, pk)
        
        return sk, pk
        
            
    def setPrivateKey(self, sk):
        """ Sets a private key and returns the public key
            This method handles the conversion to Montgomery coordinates etc.
        """
        if self.connected == False:
            raise Exception("Not connected")
        
        # swap endianess
        sk = JCCurve25519.pack_be(sk)
        
        # Generate key APDU
        SETKEY = [0x00, 0x02, 0x0, 0x00, 0x20] + sk
        
        response, sw1, sw2 = self.c.transmit(SETKEY)
    
        if sw1 != 0x90 or sw2 != 0x00:
            raise Exception("Card error")
            return False
            
        if len(response) != 32:
            raise Exception("Response is " + str(len(response)) + " byte")
        
        # Unpack and convert internally
        pkW = JCCurve25519.unpack_be(response)
        
        # convert to Curve25519 standards
        pk = JCCurve25519.weierstrass_to_montgomery(pkW)
        
        # Multiply PK by 8 (three doublings)
        pk = JCCurve25519.smul(8, pk) 
        
        return pk
        
        
    def generateSharedSecret(self, pk):
        """ Generates a shared secret from the internal private key and the
            passed public key
            This method handles the conversion to Montgomery coordinates etc.
        """
        if self.connected == False:
            raise Exception("Not connected")
        
        # Generate key APDU
        pkW = JCCurve25519.montgomery_to_weierstrass(pk);
    
        # send to card MSByte first    
        pkCard = JCCurve25519.pack_be(pkW[0]) + JCCurve25519.pack_be(pkW[1])
        GENSECRET = [0x00, 0x03, 0x0, 0x00, 0x40] + pkCard
        
        response, sw1, sw2 = self.c.transmit(GENSECRET)
    
        if sw1 != 0x90 or sw2 != 0x00:
            raise Exception("Card error")
            return False
            
        if len(response) != 32:
            raise Exception("Response is " + str(len(response)) + " byte")
        
        # Unpack and convert internally
        sharedSecretW = JCCurve25519.unpack_be(response)
        
        # convert to Curve25519 standards
        sharedSecret = JCCurve25519.weierstrass_to_montgomery(sharedSecretW)
        
        # Multiply secret by 8 (three doublings)
        sharedSecret = JCCurve25519.smul(8, sharedSecret) 
        
        return sharedSecret
        
        

def main():

    # test vector
    skTV = [0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a , 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a]
    
    pkTV = [0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a]
    
    pkN = JCCurve25519.unpack_le(pkTV)
    skN = JCCurve25519.unpack_le(skTV)
    
    skN = JCCurve25519.clamp(skN)
    
    pkTest = JCCurve25519.smul(skN, 9)
    
    print
    print "== Testing against test vector == "
    print "pkRef  = " + hex(pkN)
    print "pkTest = " + hex(pkTest)
    print "diff = " + hex(pkTest - pkN)
    print
    
    if (pkTest - pkN) != 0:
        return
        
    # Operations with Javacard
    curve = JCCurve25519()
    curve.connect()
    
    print
    print "== Testing on-card key generation"
    sk, pk = curve.generateKeypair()
    
    # Compute reference 
    pkRef = JCCurve25519.smul(sk, 9)
    diff = pkRef - pk
    
    print "pkRef  = " + hex(pkRef)
    print "pkTest = " + hex(pk)
    print "diff = " + hex(diff)
    print
    
    if diff != 0:
        return
        
    print "== Testing setting the private key"
    
    pkGen = curve.setPrivateKey(skN)
    
    diff = pkN - pkGen
    
    print "pkRef  = " + hex(pkN)
    print "pkTest = " + hex(pkGen)
    print "diff = " + hex(diff)
    print
    
    if diff != 0:
        return
        
    print "== Testing generating shared secret"
    
    pkBob = [0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f]

    sharedSecret = [0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42]
    
    pkBobN = JCCurve25519.unpack_le(pkBob)
    sharedSecretN = JCCurve25519.unpack_le(sharedSecret)
    
    ssGen = curve.generateSharedSecret(pkBobN)
    
    diff = sharedSecretN - ssGen
    
    print "secretRef  = " + hex(sharedSecretN)
    print "secretTest = " + hex(ssGen)
    print "diff = " + hex(diff)
    print
    
    if diff != 0:
        return
    
if __name__ == '__main__': 
    main()
