package tsec

import java.security.MessageDigest

import cats.effect.IO
import org.scalatest.MustMatchers
import tsec.common._
import tsec.keygen.symmetric.SymmetricKeyGen
import tsec.mac.core.JCAMacTag
import tsec.mac.imports._

class MacTests extends TestSpec with MustMatchers {

  def macTest[A](
      implicit tag: JCAMacTag[A],
      keyGen: SymmetricKeyGen[IO, A, MacSigningKey],
      pureinstance: JCAMac[IO, A]
  ): Unit = {
    behavior of tag.algorithm

    //Todo: Should be with scalacheck
    it should "Sign then verify the same encrypted data properly" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res = for {
        k        <- keyGen.generateKey
        signed   <- pureinstance.sign(dataToSign, k)
        verified <- pureinstance.verify(dataToSign, signed, k)
      } yield verified

      res.unsafeRunSync() mustBe true
    }

    it should "sign to the same message" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res: IO[Boolean] = for {
        k       <- keyGen.generateKey
        signed1 <- pureinstance.sign(dataToSign, k)
        signed2 <- pureinstance.sign(dataToSign, k)
      } yield MessageDigest.isEqual(signed1, signed2)
      res.unsafeRunSync() mustBe true
    }

    it should "not verify for different messages" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes
      val incorrect  = "hello my kekistanis".utf8Bytes

      val res = for {
        k       <- keyGen.generateKey
        signed1 <- pureinstance.sign(dataToSign, k)
        cond    <- pureinstance.verify(incorrect, signed1, k)
      } yield cond

      res.unsafeRunSync() mustBe false
    }

    it should "not verify for different keys" in {

      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res = for {
        k       <- keyGen.generateKey
        k2      <- keyGen.generateKey
        signed1 <- pureinstance.sign(dataToSign, k)
        cond    <- pureinstance.verify(dataToSign, signed1, k2)
      } yield cond

      res.unsafeRunSync() mustBe false

    }
  }

  macTest[HMACSHA1]
  macTest[HMACSHA256]
  macTest[HMACSHA384]
  macTest[HMACSHA512]

}
