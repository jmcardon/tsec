package tsec.cipher.symmetric.instances

import com.softwaremill.tagging._
import javax.crypto.{SecretKey => JSecretKey}

sealed abstract case class SecretKey[A](key: JSecretKey @@ A)

object SecretKey {
  def apply[A: SymmetricAlgorithm](key: JSecretKey) = new SecretKey(key.taggedWith[A]) {}
}