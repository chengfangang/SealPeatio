# Sealpeatio

Description

## Platforms/tools/libraries used

1. [peatio](https://github.com/InfraexDev/peatio "peatio")  
Peatio is an open-source cryptocurrency exchange implementation. We modified it a bit to meet our needs.

2. [geth](https://geth.ethereum.org/ "geth")  
Geth(full name Go Ethereum) is one of the original implementations of the Ethereum protocol.

3. Python  
Python is used to implement Sealblock multisig agent, the interface with SealBlock SGX.  
In addition to the standard Python library, other python packages and modules used are:  
  * zerorpc
  * ecdsa
    * SigningKey, SECP256k1
  * rlp
    * decode, encode
  * bitcoin
  * sha3
  * jsonrpclib
    * SimpleJSONRPCServer

4. Node.js  
Used to implement admin interface.

## Instructions to run the code
