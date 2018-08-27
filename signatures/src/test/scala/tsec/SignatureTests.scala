package tsec

import java.security.interfaces.{ECPublicKey, RSAPublicKey}

import cats.effect.IO
import org.scalatest.MustMatchers
import tsec.common._
import tsec.signature.jca._

class SignatureTests extends TestSpec with MustMatchers {

  //Todo: Property check here
  val toSign = "HItHERE!".utf8Bytes

  def sigIOTests[A](
      implicit interp: JCASigner[IO, A],
      ecKFTag: JCASigKG[IO, A]
  ): Unit = {

    behavior of s"${interp.algorithm}"

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

  def sigRSAIOTests[A](
      implicit interp: JCASigner[IO, A],
      ecKFTag: JCARSASigKG[IO, A]
  ): Unit = {
    behavior of s"${interp.algorithm}"

    it should "verify with RSA key generated from modulus and public exponent" in {
      val expression: IO[Boolean] = for {
        keyPair <- ecKFTag.generateKeyPair
        publicKey1 = keyPair.publicKey
        modulus = publicKey1.asInstanceOf[RSAPublicKey].getModulus
        publicExponent = publicKey1.asInstanceOf[RSAPublicKey].getPublicExponent
        publicKey2 <- ecKFTag.buildPublicKeyFromParameters(modulus, publicExponent)
        signed   <- interp.sign(toSign, keyPair.privateKey)
        verified1 <- interp.verifyBool(toSign, signed, publicKey1)
        verified2 <- interp.verifyBool(toSign, signed, publicKey2)
      } yield verified1 && verified2

      expression.unsafeRunSync() mustBe true
    }
  }

  def sigECIOTests[A](
      implicit interp: JCASigner[IO, A],
      ecKFTag: JCAECKG[IO, A]
  ): Unit = {
    behavior of s"${interp.algorithm}"

    it should "verify with EC key generated from public point" in {
      val expression: IO[Boolean] = for {
        keyPair <- ecKFTag.generateKeyPair
        publicKey1 = keyPair.publicKey
        publicPoint = publicKey1.asInstanceOf[ECPublicKey].getW
        publicKey2 <- ecKFTag.buildPublicKeyFromPoints(publicPoint.getAffineX, publicPoint.getAffineY)
        signed   <- interp.sign(toSign, keyPair.privateKey)
        verified1 <- interp.verifyBool(toSign, signed, publicKey1)
        verified2 <- interp.verifyBool(toSign, signed, publicKey2)
      } yield verified1 && verified2

      expression.unsafeRunSync() mustBe true
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

  sigRSAIOTests[SHA256withRSA]
  sigRSAIOTests[SHA384withRSA]
  sigRSAIOTests[SHA512withRSA]

  sigECIOTests[SHA256withECDSA]
  sigECIOTests[SHA384withECDSA]
  sigECIOTests[SHA512withECDSA]
}
