package tsec.cipher.symmetric.libsodium

import cats.effect.IO
import org.scalatest.MustMatchers
import tsec.{ScalaSodium, TestSpec}
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.PlainText
import tsec.common._

class SodiumCipherTest extends TestSpec with MustMatchers {

  behavior of "XSalsa20Poly1305"

  implicit val sodium: ScalaSodium = ScalaSodium.getSodiumUnsafe

  it should "generate key, encrypt and decrypt properly" in {
    val pt = PlainText("hi".utf8Bytes)

    (for {
      key     <- XSalsa20Poly1305.generateKey[IO]
      encrypt <- XSalsa20Poly1305.encrypt[IO](pt, key)
      decrypt <- XSalsa20Poly1305.decrypt[IO](encrypt, key)
    } yield decrypt).unsafeRunSync().content.toUtf8String mustBe pt.content.toUtf8String
  }

  it should "not decrypt properly for a wrong key" in {
    val pt = PlainText("hi".utf8Bytes)

    (for {
      key     <- XSalsa20Poly1305.generateKey[IO]
      key2     <- XSalsa20Poly1305.generateKey[IO]
      encrypt <- XSalsa20Poly1305.encrypt[IO](pt, key)
      decrypt <- XSalsa20Poly1305.decrypt[IO](encrypt, key2)
    } yield decrypt).attempt.unsafeRunSync() mustBe a[Left[CipherError, _]]
  }

}
