/**

 By David Oswald, d.f.oswald@cs.bham.ac.uk
 26 August 2015
 
 This code uses the excellent JC ant task and the GP tool written by
 Martin Paljak and available under the MIT / LGPL license (pls see
 the respective repositories for details).
 
 https://github.com/martinpaljak/ant-javacard
 https://github.com/martinpaljak/GlobalPlatformPro#license
 
 Some code was contributed by Shaima Al Amri as part of an MSc project
 
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

**/

package curve25519;

import javacard.framework.*;
import javacard.security.*; 
import javacard.framework.Applet;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacardx.crypto.Cipher;
import javacard.security.Key;
import javacard.security.KeyBuilder;

 
public class Curve25519Test extends Applet 
{
	// Bogus version number
    private static final short VERSION_NUMBER = (short)0x5519;
    
	// Bit length of prime field, this is important to get right (i.e. 256 will not work)
	// PetrS: some cards fails when 255 length is used, but works correctly with 256 as well
    private static final short keyLength = 255;

	// Curve25519 Weierstrass parameters
	//
	// most values from http://samuelkerr.com/?p=431 (though some bugs in the
	// Python scripts needed a fix)
	//
	// p =    7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
	// a =    2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144
	// b =    7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864
	// g = 04 2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a
	//        20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9
	// 
	// r =    1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
	//        2^252 + 27742317777372353535851937790883648493, cofactor 8
	
	final static byte[] p256 = {
		(byte)0x7f, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xed
	};
	
		
	final static byte[] a256 = {
		(byte)0x2a, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0x98, (byte)0x49, (byte)0x14, (byte)0xa1, (byte)0x44
	};
	
		
	final static byte[] b256 = {
		(byte)0x7b, (byte)0x42, (byte)0x5e, (byte)0xd0, (byte)0x97, (byte)0xb4, (byte)0x25, (byte)0xed, (byte)0x09, (byte)0x7b, (byte)0x42, (byte)0x5e, (byte)0xd0, (byte)0x97, (byte)0xb4, (byte)0x25, (byte)0xed, (byte)0x09, (byte)0x7b, (byte)0x42, (byte)0x5e, (byte)0xd0, (byte)0x97, (byte)0xb4, (byte)0x26, (byte)0x0b, (byte)0x5e, (byte)0x9c, (byte)0x77, (byte)0x10, (byte)0xc8, (byte)0x64
	};
	
		
	final static byte[] g256 = {
		(byte)0x04, 
		(byte)0x2a, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
		(byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xad, (byte)0x24, (byte)0x5a,
		(byte)0x20, (byte)0xae, (byte)0x19, (byte)0xa1, (byte)0xb8, (byte)0xa0, (byte)0x86, (byte)0xb4, (byte)0xe0, (byte)0x1e, (byte)0xdd, (byte)0x2c, (byte)0x77, (byte)0x48, (byte)0xd1, (byte)0x4c, 
		(byte)0x92, (byte)0x3d, (byte)0x4d, (byte)0x7e, (byte)0x6d, (byte)0x7c, (byte)0x61, (byte)0xb2, (byte)0x29, (byte)0xe9, (byte)0xc5, (byte)0xa2, (byte)0x7e, (byte)0xce, (byte)0xd3, (byte)0xd9
	};
	
		
	final static byte[] r256 = {
		(byte)0x10, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
		(byte)0x14, (byte)0xde, (byte)0xf9, (byte)0xde, (byte)0xa2, (byte)0xf7, (byte)0x9c, (byte)0xd6, (byte)0x58, (byte)0x12, (byte)0x63, (byte)0x1a, (byte)0x5c, (byte)0xf5, (byte)0xd3, (byte)0xed
	};
	
	final static short k = (short)8;
 
	// Command codes
	private static final byte GENERATE_KEYPAIR     		= (byte)0x01;     
	private static final byte LOAD_PRIVATE_KEY     		= (byte)0x02;
	private static final byte COMPUTE_SHARED_SECRET  	= (byte)0x03;

	private KeyAgreement keyAgreement;
	private ECPrivateKey ecPrivateKey;
	private ECPublicKey ecPublicKey;
	private boolean keyValid = false;
	
	private byte[] skBuffer;
    private byte[] scratchpad;
    private byte[] outBuffer;
	
    Curve25519Test() 
	{   
		// NOTE: This is not optimized for lowest memory footprint
		scratchpad = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);  
		outBuffer = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
		skBuffer = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
		keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);

		ecPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, keyLength, false);
		ecPublicKey = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, keyLength, false);
    }
    
	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new Curve25519Test().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}
	
	// Shift array left by three bit positions
	private void shift_array_right_by_3(byte[] a)
	{
		if(a.length == 0)
		{
			return;
		}
		
		byte carry = 0;
		
		for(short i = (short)(a.length - 1); i >= 1; i--)
		{
			carry = (byte)((byte)(((a[(short)(i - 1)] & 0x7) << 5)) & (byte)0xE0);
			a[i] = (byte)((byte)(a[i] >> 3) & (byte)0x1F);
			a[i] |= carry;
		}
		
		a[0] = (byte)((byte)(a[0] >> 3) & (byte)0x1F);
	}
	 
	 
	private short initKeys()
	{
		short code = 0;
		
		try {

			// Setup parameters
			// Prime field
			ecPrivateKey.setFieldFP(p256, (short)0, (short)p256.length);
			ecPublicKey.setFieldFP(p256, (short)0, (short)p256.length);

			// A coefficient
			ecPrivateKey.setA(a256, (short)0, (short)a256.length);
			ecPublicKey.setA(a256, (short)0, (short)a256.length);
			
			// B coefficient
			ecPrivateKey.setB(b256, (short)0, (short)b256.length);
			ecPublicKey.setB(b256, (short)0, (short)b256.length);

			// base point G
			ecPrivateKey.setG(g256, (short)0, (short)g256.length);
			ecPublicKey.setG(g256, (short)0, (short)g256.length);

			// order of G
			ecPrivateKey.setR(r256, (short)0, (short)32);
			ecPublicKey.setR(r256, (short)0, (short)32);
/* BUGBUG: if not commented, this will emit CryptoException.ILLEGAL_VALUE
			// Note: most cards ignore cofactor internally
			ecPrivateKey.setK(k);
			ecPublicKey.setK(k);
/**/
		}
		catch (CryptoException e)
		{code = e.getReason();}
		catch (Exception e)                
		{code = (short)0xEEEE;}
		
		return code;
	}

	public void process(APDU apdu) 
	{
		short code = 0;
		apdu.setIncomingAndReceive();
		final short in_length = apdu.getIncomingLength();
		
		byte[] buf = apdu.getBuffer();

		if (selectingApplet()) 
		{
			Util.setShort(buf, (short) 0, VERSION_NUMBER);
			apdu.setOutgoingAndSend((short) 0, (short) 2);
			return;
		}

		switch (buf[ISO7816.OFFSET_INS]) 
		{
			// Generate a random keypair on card
			// NOTE: This is debug / PoC code only, NEVER use in real code ...
			// Outputs the private key for debug purposes (OBVIOUSLY)
			case GENERATE_KEYPAIR:	
			
				// Generate random key
				RandomData r = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
				r.generateData(skBuffer, (short)0, (short)32);

				// Curve25519 clamping (not fully needed due to shift below)
				skBuffer[0] &= (byte)0x7F;
				skBuffer[0] |= (byte)0x40;
				skBuffer[31] &= (byte)0xF8;

				// Shift by 3 (the three remaining double operations are done on the PC side)
				shift_array_right_by_3(skBuffer);


				code = initKeys();

				if(code == 0)
				{

					try
					{
						// Set (scalar >> 3)
						ecPrivateKey.setS(skBuffer, (short)0, (short)skBuffer.length);

						// NOTE: This is debug / PoC code only, NEVER use in real code ...
						// Output the private key for debug purposes (OBVIOUSLY)
						ecPrivateKey.getS(buf, (short)0);
						
						// Compute the corresponding public key
						keyAgreement.init(ecPrivateKey); 
						short len = keyAgreement.generateSecret(g256, (short)0, (short)g256.length, buf, (short)32);

						apdu.setOutgoingAndSend((short) 0, (short)64);
					} 
					catch (CryptoException e)      
					{code = e.getReason();}
					catch (Exception e)                
					{code = (short)0xEEEE;}
				}
				
				if(code != (short)0)
				{
					Util.setShort(buf, (short) 0, code);
					apdu.setOutgoingAndSend((short) 0, (short) 2);
				}
				else{
					keyValid = true;
				}
			break;
			
			// Load a private key and generate the corresponding public key
			case LOAD_PRIVATE_KEY: 
			
				if(in_length != (short)32)
				{
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				}
				
				if(initKeys() != 0)
				{
					Util.setShort(buf, (short) 0, code);
					apdu.setOutgoingAndSend((short) 0, (short) 2);
					return;
				}
				
				// NOTE: Input expected MSByte first
				Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, skBuffer, (short)0, (short)skBuffer.length);
				
				// Curve25519 clamping 
				skBuffer[0] &= (byte)0x7F;
				skBuffer[0] |= (byte)0x40;
				skBuffer[31] &= (byte)0xF8;

				// Shift by 3
				shift_array_right_by_3(skBuffer);

				try 
				{
					// Set scalar
					ecPrivateKey.setS(skBuffer, (short)0, (short)skBuffer.length);
					
					// Compute the corresponding public key
					// NOTE: To make this a valid Curve25519 standard public key,
					//       3 double operations are required on the PC side
					keyAgreement.init(ecPrivateKey); 
					
					short len = keyAgreement.generateSecret(g256, (short)0, (short)g256.length, buf, (short)0);
					
					apdu.setOutgoingAndSend((short) 0, (short)32);
				} 
				catch (CryptoException e)      
				{code = e.getReason();}
				catch (Exception e)                
				{code = (short)0xEEEE;}

				if(code != (short)0)
				{
					Util.setShort(buf, (short) 0, code);
					apdu.setOutgoingAndSend((short) 0, (short) 2);
				}
				else
				{
					keyValid = true;
				}
			break;
			
			// Compute shared secret given a public key (X, Y in Weierstrass form)
			case COMPUTE_SHARED_SECRET: 
				if(in_length != (short)64 || !keyValid)
				{
					ISOException.throwIt(ISO7816.SW_DATA_INVALID);
				}
				
				// Add start byte required by Javacard
				scratchpad[0] = (byte)0x04;
				
				// Copy public point (X, Y, MSByte first)
				Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, scratchpad, (short)1, (short)64);
				
				try 
				{
					// Compute the corresponding shared secret key
					keyAgreement.init(ecPrivateKey); 
					short len = keyAgreement.generateSecret(scratchpad, (short)0, (short)65, buf, (short)0);
					
					// Send back 32-byte shared secret (again, to be doubled three times)
					apdu.setOutgoingAndSend((short) 0, (short)32);
				} 
				catch (CryptoException e)      
				{code = e.getReason();}
				catch (Exception e)                
				{code = (short)0xEEEE;}
					
				if(code != (short)0)
				{
					Util.setShort(buf, (short) 0, code);
					apdu.setOutgoingAndSend((short) 0, (short) 2);
				}
				
			break;
			
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}
