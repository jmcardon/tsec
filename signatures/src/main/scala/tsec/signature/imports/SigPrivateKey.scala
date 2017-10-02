package tsec.signature.imports

import java.security.PrivateKey

import shapeless.tag.@@

final case class SigPrivateKey[A](key: PrivateKey @@ A)

object SigPrivateKey {
  def fromKey[A](privateKey: PrivateKey): SigPrivateKey[A] = SigPrivateKey[A](shapeless.tag[A](privateKey))
}
