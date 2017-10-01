package tsec

import org.scalatest.MustMatchers
import tsec.core.ByteUtils._
import tsec.core.JKeyGenerator
import tsec.mac.imports.{MacSigningKey, _}

class MacTests extends TestSpec with MustMatchers {


  def macTest[T: ByteAux](implicit keyGen: JKeyGenerator[T, MacSigningKey, MacKeyBuildError], tag: MacTag[T]): Unit = {
    behavior of tag.algorithm

    val instance = JCAMacImpure[T]

    it should "Sign then verify the same encrypted data properly" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res: Either[MacError, Boolean] = for {
        k <- keyGen.generateKey()
        signed <- instance.sign(dataToSign, k)
        verified <- instance.verify(dataToSign, signed, k)
      } yield verified

      res mustBe Right(true)
    }

    it should "sign to the same message" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res: Either[MacError, Boolean] = for {
        k <- keyGen.generateKey()
        signed1 <- instance.algebra.sign(dataToSign, k)
        signed2 <- instance.algebra.sign(dataToSign, k)
      } yield constantTimeEquals(signed1, signed2)
      res mustBe Right(true)
    }

    it should "not verify for different messages" in {
      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes
      val incorrect = "hello my kekistanis".utf8Bytes

      val res: Either[MacError, Boolean] = for {
        k <- keyGen.generateKey()
        signed1 <- instance.sign(dataToSign, k)
        cond <- instance.verify(incorrect,signed1, k)
      } yield cond

      res mustBe Right(false)
    }

    it should "not verify for different keys" in {

      val dataToSign = "awwwwwwwwwwwwwwwwwwwwwww YEAH".utf8Bytes

      val res: Either[MacError, Boolean] = for {
        k <- keyGen.generateKey()
        k2 <- keyGen.generateKey()
        signed1 <- instance.sign(dataToSign, k)
        cond <- instance.verify(dataToSign,signed1, k2)
      } yield cond

      res mustBe Right(false)

    }
  }

  macTest[HMACSHA1]
  macTest[HMACSHA256]
  macTest[HMACSHA384]
  macTest[HMACSHA512]

}