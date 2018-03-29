package tsec

import cats.effect.IO
import org.scalatest.MustMatchers
import tsec.common._
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.bouncy._
import tsec.cipher.symmetric.libsodium.{SodiumKey, CryptoSecretBox => SodiumSalsa, OriginalChacha20}
import tsec.cipher.symmetric.libsodium.{XChacha20AEAD => SodiumXChaCha, IETFChacha20}
import tsec.libsodium.ScalaSodium

class CipherEqualityTest extends TestSpec with MustMatchers {

  /** These are all libsodium test vectors **/
  val fixedPTRaw = "Ladies and Gentlemen of the class of '99: If I could offer you only one " +
    "tip for the future, sunscreen would be it."
  val fixedPT   = PlainText(fixedPTRaw.utf8Bytes)
  val fixedAAD  = AAD("50515253c0c1c2c3c4c5c6c7".hexBytesUnsafe)
  val fixedIv24 = "07000000404142434445464748494a4b0000000000000000".hexBytesUnsafe
  val fixedIv8  = "0700000040414243".hexBytesUnsafe
  val fixedIv12 = "070000004041424344454647".hexBytesUnsafe
  val fixedKey  = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f".hexBytesUnsafe

  def AuthEncryptorTest[C1, C2](testName: String)(
      implicit LSEncryptor: AuthEncryptor[IO, C1, SodiumKey],
      BCEncryptor: AuthEncryptor[IO, C2, BouncySecretKey]
  ): Unit = {

    behavior of s"$testName: Libsodium and Bouncy Castle"

    it should "Encrypt and decrypt equally" in {
      val expr = for {
        c1 <- LSEncryptor.encrypt(fixedPT, SodiumKey(fixedKey), Iv(fixedIv24))
        c2 <- BCEncryptor.encrypt(fixedPT, BouncySecretKey(fixedKey), Iv(fixedIv24))
        d1 <- LSEncryptor.decrypt(c1, SodiumKey(fixedKey))
        d2 <- BCEncryptor.decrypt(c2, BouncySecretKey(fixedKey))
      } yield (c1, c2, d1.toUtf8String == d2.toUtf8String && d2.toUtf8String == fixedPTRaw)

      val (l, r, cond) = expr.unsafeRunSync()

      l.content.toHexString mustBe r.content.toHexString
      cond mustBe true
    }

    it should "Encrypt equally detached" in {
      val expr = for {
        c1 <- LSEncryptor.encryptDetached(fixedPT, SodiumKey(fixedKey), Iv(fixedIv24))
        c2 <- BCEncryptor.encryptDetached(fixedPT, BouncySecretKey(fixedKey), Iv(fixedIv24))
        d1 <- LSEncryptor.decryptDetached(c1._1, SodiumKey(fixedKey), c1._2)
        d2 <- BCEncryptor.decryptDetached(c2._1, BouncySecretKey(fixedKey), c2._2)
      } yield (c1, c2, d1.toUtf8String == d2.toUtf8String && d1.toUtf8String == fixedPTRaw)

      val ((ct1, t1), (ct2, t2), cond) = expr.unsafeRunSync()

      ct1.content.toHexString mustBe ct2.content.toHexString
      t1.toHexString mustBe t2.toHexString
      cond mustBe true
    }
  }

  def AADEncryptorTest[C1, C2](testName: String, fixedIv: Array[Byte])(
      implicit LSEncryptor: AADEncryptor[IO, C1, SodiumKey],
      BCEncryptor: AADEncryptor[IO, C2, BouncySecretKey]
  ): Unit = {
    def coerceKey(k: SodiumKey[C1]): BouncySecretKey[C2] =
      BouncySecretKey[C2](k)
    def coerceIv(k: Iv[C1]): Iv[C2] =
      Iv[C2](k)

    behavior of s"$testName: Libsodium and Bouncy Castle"

    it should "Encrypt and decrypt equally" in {
      val expr = for {
        c1 <- LSEncryptor.encrypt(fixedPT, SodiumKey(fixedKey), Iv(fixedIv))
        c2 <- BCEncryptor.encrypt(fixedPT, BouncySecretKey(fixedKey), Iv(fixedIv))
        d1 <- LSEncryptor.decrypt(c1, SodiumKey(fixedKey))
        d2 <- BCEncryptor.decrypt(c2, BouncySecretKey(fixedKey))
      } yield (c1, c2, d1.toUtf8String == d2.toUtf8String && d1.toUtf8String == fixedPTRaw)

      val (l, r, cond) = expr.unsafeRunSync()

      l.content.toHexString mustBe r.content.toHexString
      cond mustBe true
    }

    it should "Encrypt and decrypt equally with AAD" in {
      val expr = for {
        c1 <- LSEncryptor.encryptWithAAD(fixedPT, SodiumKey(fixedKey), Iv(fixedIv), fixedAAD)
        c2 <- BCEncryptor.encryptWithAAD(fixedPT, BouncySecretKey(fixedKey), Iv(fixedIv), fixedAAD)
        d1 <- LSEncryptor.decryptWithAAD(c1, SodiumKey(fixedKey), fixedAAD)
        d2 <- BCEncryptor.decryptWithAAD(c2, BouncySecretKey(fixedKey), fixedAAD)
      } yield (c1, c2, d1.toUtf8String == d2.toUtf8String && d1.toUtf8String == fixedPTRaw)

      val (l, r, cond) = expr.unsafeRunSync()

      l.content.toHexString mustBe r.content.toHexString
      cond mustBe true
    }

    it should "Encrypt equally detached" in {
      val expr = for {
        c1 <- LSEncryptor.encryptDetached(fixedPT, SodiumKey(fixedKey), Iv(fixedIv))
        c2 <- BCEncryptor.encryptDetached(fixedPT, BouncySecretKey(fixedKey), Iv(fixedIv))
        d1 <- LSEncryptor.decryptDetached(c1._1, SodiumKey(fixedKey), c1._2)
        d2 <- BCEncryptor.decryptDetached(c2._1, BouncySecretKey(fixedKey), c2._2)
      } yield (c1, c2, d1.toUtf8String == d2.toUtf8String && d1.toUtf8String == fixedPTRaw)

      val ((ct1, t1), (ct2, t2), cond) = expr.unsafeRunSync()

      ct1.content.toHexString mustBe ct2.content.toHexString
      t1.toHexString mustBe t2.toHexString
      cond mustBe true
    }

    it should "Encrypt equally detached with AAD" in {
      val expr = for {
        c1 <- LSEncryptor.encryptWithAADDetached(fixedPT, SodiumKey(fixedKey), Iv(fixedIv), fixedAAD)
        c2 <- BCEncryptor.encryptWithAADDetached(fixedPT, BouncySecretKey(fixedKey), Iv(fixedIv), fixedAAD)
        d1 <- LSEncryptor.decryptWithAADDetached(c1._1, SodiumKey(fixedKey), fixedAAD, c1._2)
        d2 <- BCEncryptor.decryptWithAADDetached(c2._1, BouncySecretKey(fixedKey), fixedAAD, c2._2)
      } yield (c1, c2, d1.toUtf8String == d2.toUtf8String && d1.toUtf8String == fixedPTRaw)

      val ((ct1, t1), (ct2, t2), cond) = expr.unsafeRunSync()

      ct1.content.toHexString mustBe ct2.content.toHexString
      t1.toHexString mustBe t2.toHexString
      cond mustBe true
    }
  }

  implicit val sodium     = ScalaSodium.getSodiumUnsafe
  implicit val salsaIvGen = SodiumSalsa.defaultIvGen[IO]
  AuthEncryptorTest[SodiumSalsa, XSalsa20Poly1305](SodiumSalsa.algorithm)

  implicit val XchachaIETFIVGen = SodiumXChaCha.defaultIvGen[IO]
  AADEncryptorTest[SodiumXChaCha, XChaCha20Poly1305](SodiumXChaCha.algorithm, fixedIv24)

  implicit val chachaIVGen = OriginalChacha20.defaultIvGen[IO]
  AADEncryptorTest[OriginalChacha20, ChaCha20Poly1305](OriginalChacha20.algorithm, fixedIv8)

  implicit val chachaIETFIvGen = ChaCha20Poly1305IETF.defaultIvGen[IO]
  AADEncryptorTest[IETFChacha20, ChaCha20Poly1305IETF](IETFChacha20.algorithm, fixedIv12)

}
