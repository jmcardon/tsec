package tsec.mac.instance

import javax.crypto.{SecretKey => JSecretKey}

import shapeless.tag
import shapeless.tag.@@

sealed abstract case class MacSigningKey[T](key: JSecretKey @@ T)

object MacSigningKey {
  def apply[T: MacTag](key: JSecretKey) = new MacSigningKey[T](tag[T](key)) {}
}
