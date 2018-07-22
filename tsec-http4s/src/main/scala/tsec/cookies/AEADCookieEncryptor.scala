package tsec.cookies

import cats.effect.Sync
import cats.syntax.all._
import tsec.cipher.common.padding.NoPadding
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.jca._
import tsec.common._

object AEADCookieEncryptor {

  def signAndEncrypt[F[_], A](message: String, aad: AAD, key: SecretKey[A])(
      implicit authEncryptor: JAuthEncryptor[F, A],
      ivStrat: IvGen[F, A],
      F: Sync[F]
  ): F[AEADCookie[A]] =
    if (message.isEmpty)
      F.raiseError(EncryptError("Cannot encrypt an empty string!"))
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
      for {
        aad <- split(1).b64Bytes
          .fold[F[AAD]](F.raiseError(DecryptError("Could not decode cookie")))(arr => F.pure(AAD(arr)))
        rawCTBytes <- split(0).b64Bytes
          .fold[F[Array[Byte]]](F.raiseError(DecryptError("Could not decode cookie")))(F.pure)
        cipherText <- F.fromEither(CTOPS.ciphertextFromArray[A, GCM, NoPadding](rawCTBytes))
        decrypted  <- authEncryptor.decryptWithAAD(cipherText, key, aad)
      } yield decrypted.toUtf8String
    }
  }

}
