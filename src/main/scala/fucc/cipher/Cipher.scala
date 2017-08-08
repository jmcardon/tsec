package fucc.cipher

import javax.crypto.SecretKey

case class ClearText(content: Array[Byte])
case class CipherText(content: Array[Byte])

trait Cipher[A,M,P] {
  def encrypt(clearText: ClearText)(implicit key: SecretKey): Either[CipherError, CipherText]
  def decrypt(cipherText: CipherText)(implicit key: SecretKey): Either[CipherError, ClearText]
}