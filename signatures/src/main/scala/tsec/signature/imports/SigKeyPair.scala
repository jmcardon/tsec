package tsec.signature.imports

import java.security.KeyPair

case class SigKeyPair[A](privateKey: SigPrivateKey[A], publicKey: SigPublicKey[A])

object SigKeyPair {
  def fromKeyPair[A](keypair: KeyPair): SigKeyPair[A] =
    SigKeyPair[A](SigPrivateKey.fromKey[A](keypair.getPrivate), SigPublicKey.fromKey[A](keypair.getPublic))
}
