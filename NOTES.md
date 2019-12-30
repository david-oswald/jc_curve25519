- NXP J3H145G P60 card emit exception when ecPrivateKey.setK(k); or ecPublicKey.setK(k); is called

Speed test:
0) Alcor Micro USB Smart Card Reader 0
== Testing on-card key generation
Execution time: 273.81950000000006 ms
== Testing setting the private key
Execution time: 255.55810000000002 ms
== Testing generating shared secret
Execution time: 77.03400000000005 ms


On-card key generation (generate 32 random bytes, perform one ECC operation): 273 ms
Set private key (perform one ECC operation): 255 ms
Generate shared secret (perform one ECC operation with pre-set private key): 77 ms