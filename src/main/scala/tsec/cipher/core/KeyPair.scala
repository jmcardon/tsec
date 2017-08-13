package tsec.cipher.core

case class KeyPair[A,B](privateKey: PrivateKey[A], publicKey: PublicKey[B])