package fucc.symmetric

import javax.crypto.SecretKey


trait KeyGenerator[T] {
  def generateKey(): SecretKey
}



