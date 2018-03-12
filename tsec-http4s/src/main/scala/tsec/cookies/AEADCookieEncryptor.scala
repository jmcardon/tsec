package tsec.cookies

import cats.effect.Sync
import cats.syntax.all._
import tsec.cipher.common.padding.NoPadding
import tsec.common._
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.core._
import tsec.cipher.symmetric.imports._

object AEADCookieEncryptor {

  def signAndEncrypt[F[_]: Sync, A: AES](message: String, aad: AAD, key: SecretKey[A])(
      implicit authEncryptor: JAuthEncryptor[F, A],
      ivStrat: IvGen[F, A]
  ): F[AEADCookie[A]] =
    if (message.isEmpty)
      Sync[F].raiseError(EncryptError("Cannot encrypt an empty string!"))
    else {
      val messageBytes = message.utf8Bytes
      for {
        iv        <- ivStrat.genIv
        encrypted <- authEncryptor.encryptWithAAD(PlainText(messageBytes), key, iv, aad)
      } yield AEADCookie.fromEncrypted[A](encrypted, aad)
    }

  def retrieveFromSigned[F[_], A: AES](message: AEADCookie[A], key: SecretKey[A])(
      implicit authEncryptor: JAuthEncryptor[F, A],
      F: Sync[F],
      ivStrat: IvGen[F, A]
  ): F[String] = {
    val split = message.split("-")
    if (split.length != 2)
      F.raiseError(DecryptError("Could not decode cookie"))
    else {
      val aad = AAD(split(1).base64Bytes)
      for {
        cipherText <- F.fromEither(CTOPS.ciphertextFromArray[A, GCM, NoPadding](split(0).base64Bytes))
        decrypted  <- authEncryptor.decryptWithAAD(cipherText, key, aad)
      } yield decrypted.toUtf8String
    }
  }

}
