package fucc.symmetric

import javax.crypto.{SecretKey => JSecretKey}

import com.softwaremill.tagging.@@

package object instances {
  type JSymmetric[T] = JSecretKey @@ T

}
