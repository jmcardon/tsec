package tsec.signature.instance

case class SigKeyPair[A, B](privateKey: SigPrivateKey[A], publicKey: SigPublicKey[B])

