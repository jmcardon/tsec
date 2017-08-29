package tsec.cipher.symmetric.instances

import javax.crypto.{SecretKey => JSecretKey}
import shapeless.tag
import shapeless.tag.@@

sealed abstract case class SecretKey[A](key: JSecretKey @@ A)

object SecretKey {
  def apply[A: SymmetricAlgorithm](key: JSecretKey) = new SecretKey(tag[A](key)) {}
}