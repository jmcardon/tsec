package tsec.signature.core

case class SigKeyPair[A, B](privateKey: SigPrivateKey[A], publicKey: SigPublicKey[B])

