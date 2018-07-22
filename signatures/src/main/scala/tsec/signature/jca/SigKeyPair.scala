package tsec.signature.jca

import java.security.KeyPair

case class SigKeyPair[A](privateKey: SigPrivateKey[A], publicKey: SigPublicKey[A])

object SigKeyPair {
  def fromKeyPair[A](keypair: KeyPair): SigKeyPair[A] =
    SigKeyPair[A](SigPrivateKey[A](keypair.getPrivate), SigPublicKey[A](keypair.getPublic))
}
