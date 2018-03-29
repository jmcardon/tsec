package tsec


import cats.effect.IO
import org.scalatest.MustMatchers
import tsec.common._
import tsec.signature.jca._

class SignatureTests extends TestSpec with MustMatchers {

  //Todo: Property check here
  val toSign = "HItHERE!".utf8Bytes

  def sigIOTests[A](
      implicit algoTag: JCASigTag[A],
      interp: JCASigner[IO, A],
      ecKFTag: JCASigKG[IO, A]
  ): Unit = {

    behavior of s"${algoTag.algorithm}"

    it should "sign and verify properly for correct keypair" in {

      val expression: IO[Boolean] = for {
        keyPair <- ecKFTag.generateKeyPair
        signed  <- interp.sign(toSign, keyPair.privateKey)
        verify  <- interp.verifyBool(toSign, signed, keyPair.publicKey)
      } yield verify

      expression.unsafeRunSync() mustBe true
    }

    it should "not verify for a wrong key pair" in {
      val expression: IO[Boolean] = for {
        keyPair1 <- ecKFTag.generateKeyPair
        keyPair2 <- ecKFTag.generateKeyPair
        signed   <- interp.sign(toSign, keyPair1.privateKey)
        verify   <- interp.verifyBool(toSign, signed, keyPair2.publicKey)
      } yield verify

      expression.unsafeRunSync() mustBe false
    }

  }

  sigIOTests[SHA1withDSA]
  sigIOTests[SHA224withDSA]
  sigIOTests[SHA256withDSA]
  sigIOTests[MD2withRSA]
  sigIOTests[MD5withRSA]
  sigIOTests[SHA1withRSA]
  sigIOTests[SHA256withRSA]
  sigIOTests[SHA384withRSA]
  sigIOTests[SHA512withRSA]
  sigIOTests[SHA1withECDSA]
  sigIOTests[SHA224withECDSA]
  sigIOTests[SHA256withECDSA]
  sigIOTests[SHA384withECDSA]
  sigIOTests[SHA512withECDSA]
  sigIOTests[NONEwithECDSA]

}
