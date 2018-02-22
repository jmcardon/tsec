package tsec

import java.security.MessageDigest

import cats.effect.IO
import org.scalatest.MustMatchers
import tsec.common._
import tsec.common.JKeyGenerator
import tsec.mac.core.JCAMacTag
import tsec.mac.imports._

class MacTests extends TestSpec with MustMatchers {

  def macTest[T](
      implicit keyGen: JKeyGenerator[T, MacSigningKey, MacKeyBuildError],
      tag: JCAMacTag[T],
      pureinstance: JCAMac[T]
  ): Unit = {
    behavior of tag.algorithm

    //Todo: Should be with scalacheck
    it should "Sign then verify the same encrypted data properly" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res = for {
        k        <- keyGen.generateLift[IO]
        signed   <- pureinstance.sign[IO](dataToSign, k)
        verified <- pureinstance.verify[IO](dataToSign, signed, k)
      } yield verified

      res.unsafeRunSync() mustBe true
    }

    it should "sign to the same message" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res: IO[Boolean] = for {
        k       <- keyGen.generateLift[IO]
        signed1 <- pureinstance.sign[IO](dataToSign, k)
        signed2 <- pureinstance.sign[IO](dataToSign, k)
      } yield MessageDigest.isEqual(signed1, signed2)
      res.unsafeRunSync() mustBe true
    }

    it should "not verify for different messages" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes
      val incorrect  = "hello my kekistanis".utf8Bytes

      val res = for {
        k       <- keyGen.generateLift[IO]
        signed1 <- pureinstance.sign[IO](dataToSign, k)
        cond    <- pureinstance.verify[IO](incorrect, signed1, k)
      } yield cond

      res.unsafeRunSync() mustBe false
    }

    it should "not verify for different keys" in {

      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res = for {
        k       <- keyGen.generateLift[IO]
        k2      <- keyGen.generateLift[IO]
        signed1 <- pureinstance.sign[IO](dataToSign, k)
        cond    <- pureinstance.verify[IO](dataToSign, signed1, k2)
      } yield cond

      res.unsafeRunSync() mustBe false

    }
  }

  macTest[HMACSHA1]
  macTest[HMACSHA256]
  macTest[HMACSHA384]
  macTest[HMACSHA512]

}
