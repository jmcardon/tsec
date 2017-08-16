package tsec.cipher.symmetric

import javax.crypto.{SecretKey => JSecretKey}
import com.softwaremill.tagging._

package object instances {
  type JEncryptionKey[T] = JSecretKey @@ T
}
