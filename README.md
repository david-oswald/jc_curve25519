# jc_curve25519

Javacard implementation of Curve25519 (prototype, work-in-progress). 

This code is in the public domain.

## Requirements
- Javacard 3.0.1 or higher (currently developed on J2D081)
- JCDK 3.0.3 or higher (see below)
- Working Java SDK / ant installation
- For testing: Python with smartcard packages

## Building
This code uses the excellent JC Ant task and the GP tool for building and installation. Compile using:
	
	ant curve
	
This assumes you have a Javacard 3.0.3 SDK (JCDK) in the folder pointed to by build.xml:

	<property name="JC303" value="../jc303" />

Here, we assume the JCDK is one folder up. Change as needed. JCDK packages can e.g. be found at https://github.com/martinpaljak/oracle_javacard_sdks

JC Ant and the GP tool are written by Martin Paljak (https://github.com/martinpaljak) and are available under the MIT / LGPL license (see the respective repositories for details).

## Installation
Upload .cap file after compilation to card using gp:

	gp --install curve25519_jc303.cap

If the applet was installed before, remove it first:

	gp --uninstall curve25519_jc303.cap	

## Testing
Using Python, execute jc_curve25519.py. Requires pyScard to communicate with card. A convenient way under Windows is using Anaconda (http://continuum.io/downloads). An example output could be:

	== Testing against test vector == 
	pkRef  = 0x6a4e9baa8ea9a4ebf41a38260d3abf0d5af73eb4dc7d8b7454a7308909f02085L
	pkTest = 0x6a4e9baa8ea9a4ebf41a38260d3abf0d5af73eb4dc7d8b7454a7308909f02085L
	diff = 0x0L

	== Available readers:
	0) SCM Microsystems Inc. SCR35xx USB Smart Card Reader 0
	 Connecting to first reader ... 
	 ATR: 3B F9 18 00 00 81 31 FE 45 4A 32 44 30 38 31 5F 50 56 B6
	 App selected

	== Testing on-card key generation
	pkRef  = 0x336f019040df969295182ef7cc4873f2d406a3e878cea1c035d740bdbab673aeL
	pkTest = 0x336f019040df969295182ef7cc4873f2d406a3e878cea1c035d740bdbab673aeL
	diff = 0x0L

	== Testing setting the private key
	pkRef  = 0x6a4e9baa8ea9a4ebf41a38260d3abf0d5af73eb4dc7d8b7454a7308909f02085L
	pkTest = 0x6a4e9baa8ea9a4ebf41a38260d3abf0d5af73eb4dc7d8b7454a7308909f02085L
	diff = 0x0L

	== Testing generating shared secret
	secretRef  = 0x4217161e3c9bf076339ed147c9217ee0250f3580f43b8e72e12dcea45b9d5d4aL
	secretTest = 0x4217161e3c9bf076339ed147c9217ee0250f3580f43b8e72e12dcea45b9d5d4aL
	diff = 0x0L

## Execution times
The execution times are measured using timeit.default_timer. These timings include the communication overhead for sending and receiving data, but not the post-processing in Python:

| Operation | NXP J2D081 contact | NXP J3H145 contact | NXP JCOP4 J3R180 contact | 
| ------------- |-------------:| -----:| -------------:|
| On-card key generation (generate 32 random bytes, perform one ECC operation)   | 624 ms | 272 ms  | 121 ms |
| Set private key (perform one ECC operation)     |  618 ms |  255 ms | 92 ms | 
| Generate shared secret (perform one ECC operation with pre-set private key)    | 122 ms |  77  ms | 39 ms |
	
The timings are very consistent over multiple executions.
	
## Acknowledgements
Thanks to Peter Schwabe for his helpful comments and suggestions and to Shaima Al Amri, who worked on this topic for an MSc project.

## License
Public domain, see LICENSE

## Useful links
* https://docs.oracle.com/javacard/3.0.5/api/index.html
* https://github.com/martinpaljak
* http://samuelkerr.com/?p=431 
