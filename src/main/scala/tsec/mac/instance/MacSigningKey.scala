package tsec.mac.instance

import javax.crypto.{SecretKey => JSecretKey}
import com.softwaremill.tagging._
sealed abstract case class MacSigningKey[T](key: JSecretKey @@ T)
object MacSigningKey {
  def apply[T: MacTag](key: JSecretKey) = new MacSigningKey[T](key.taggedWith[T]){}
}
