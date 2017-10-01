package tsec.cipher.common

case class KeyPair[A, B](privateKey: PrivateKey[A], publicKey: PublicKey[B])
