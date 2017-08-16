package tsec.cipher.asymmetric.instances

import java.security.{PrivateKey => JPrivateKey, PublicKey => JPublicKey}
import javax.crypto.{Cipher => JCipher}
import cats.syntax.either._
import tsec.cipher.asymmetric.core.{AsymmetricAlgorithm, AsymmetricCipherAlgebra}
import tsec.cipher.common._
import tsec.cipher.common.mode.ModeKeySpec

class JCAAsymmetricCipher[A, M, P](
    implicit algoTag: AsymmetricAlgorithm[A],
    modeSpec: ModeKeySpec[M],
    paddingTag: Padding[P]
) extends AsymmetricCipherAlgebra[Either[CipherError, ?], A, M, P, JPrivateKey, JPublicKey] {

  type C = JCipher

  private def initEncrypter(encrypter: JCipher, key: PrivateKey[JPrivateKey]): Either[KeyError, Unit] =
    Either.catchNonFatal(encrypter.init(JCipher.ENCRYPT_MODE, key.key)).leftMap(e => KeyError(e.getMessage))

  private def initDecrypter(decrypter: JCipher, key: PublicKey[JPublicKey]): Either[KeyError, Unit] =
    Either.catchNonFatal(decrypter.init(JCipher.DECRYPT_MODE, key.key)).leftMap(e => KeyError(e.getMessage))

  def genInstance: Either[CipherError, JCipher] =
    Either
      .catchNonFatal(
        JCipher.getInstance(s"${algoTag.algorithm}/${modeSpec.algorithm}/${paddingTag.algorithm}")
      )
      .leftMap(e => InstanceInitError(e.getMessage))

  override def encrypt(
      plainText: PlainText[A, M, P],
      key: PrivateKey[JPrivateKey]
  ): Either[CipherError, CipherText[A, M, P]] =
    for {
      instance <- genInstance
      _        <- initEncrypter(instance, key)
      enc      <- Either.catchNonFatal(instance.doFinal(plainText.content)).leftMap(e => EncryptError(e.getMessage))
    } yield CipherText(enc, Array.empty[Byte])

  override def decrypt(
      cipherText: CipherText[A, M, P],
      key: PublicKey[JPublicKey]
  ): Either[CipherError, PlainText[A, M, P]] =
    for {
      instance <- genInstance
      _        <- initDecrypter(instance, key)
      enc      <- Either.catchNonFatal(instance.doFinal(cipherText.content)).leftMap(e => DecryptError(e.getMessage))
    } yield PlainText(enc)
}

object JCAAsymmetricCipher {

  def getCipher[A: AsymmetricAlgorithm, M: ModeKeySpec, P: Padding]
    : Either[NoSuchInstanceError, JCAAsymmetricCipher[A, M, P]] = {
    val x = new JCAAsymmetricCipher[A, M, P]()
    x.genInstance.map(_ => x).leftMap(_ => NoSuchInstanceError)
  }

  def getCipherUnsafe[A: AsymmetricAlgorithm, M: ModeKeySpec, P: Padding]: JCAAsymmetricCipher[A, M, P] =
    new JCAAsymmetricCipher[A, M, P]
}
