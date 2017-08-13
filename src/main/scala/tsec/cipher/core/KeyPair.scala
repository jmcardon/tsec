package tsec.cipher.core

case class KeyPar[A,B](privateKey: PrivateKey[A], publicKey: PublicKey[B])