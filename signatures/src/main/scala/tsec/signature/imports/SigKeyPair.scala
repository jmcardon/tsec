package tsec.signature.imports

import java.security.KeyPair

import tsec.signature.core.SigAlgoTag

case class SigKeyPair[A](privateKey: SigPrivateKey[A], publicKey: SigPublicKey[A])

object SigKeyPair {
  def fromKeyPair[A: SigAlgoTag](keypair: KeyPair): SigKeyPair[A] =
    SigKeyPair[A](SigPrivateKey[A](keypair.getPrivate), SigPublicKey[A](keypair.getPublic))
}
