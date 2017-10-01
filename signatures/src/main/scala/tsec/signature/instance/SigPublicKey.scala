package tsec.signature.instance

import java.security.PublicKey

import shapeless.tag.@@

final case class SigPublicKey[B](key: PublicKey @@ B)

object SigPublicKey {
  def fromKey[A](key: PublicKey): SigPublicKey[A] = SigPublicKey[A](shapeless.tag[A](key))
}
