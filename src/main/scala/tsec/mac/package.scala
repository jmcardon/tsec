package tsec

import javax.crypto.{SecretKey => JSecretKey}

import com.softwaremill.tagging._
import tsec.mac.instance.MacTag

package object mac {
  type MacKey[T] = JSecretKey @@ T
  def tagKey[T: MacTag](s: JSecretKey): MacKey[T] = s.taggedWith[T]
}
