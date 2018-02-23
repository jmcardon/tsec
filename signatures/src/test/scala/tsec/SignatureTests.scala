package tsec

import java.security.Security

import tsec.common._
import cats.effect.{Effect, IO}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.scalatest.MustMatchers
import tsec.signature.core.{KFTag, SigAlgoTag}
import tsec.signature.imports._

class SignatureTests extends TestSpec with MustMatchers {

  //Todo: Property check here
  val toSign        = "HItHERE!".utf8Bytes
  val F: Effect[IO] = IO.ioEffect

  if (Security.getProvider("BC") == null)
    Security.addProvider(new BouncyCastleProvider())

  def sigIOTests[A](
      implicit algoTag: SigAlgoTag[A],
      interp: JCASigner[IO, A],
      ecKFTag: KFTag[A]
  ): Unit = {

    behavior of s"${algoTag.algorithm}"

    it should "sign and verify properly for correct keypair" in {

      val expression: IO[Boolean] = for {
        keyPair <- F.fromEither[SigKeyPair[A]](ecKFTag.generateKeyPair)
        signed  <- interp.sign(toSign, keyPair.privateKey)
        verify  <- interp.verify(toSign, signed, keyPair.publicKey)
      } yield verify

      expression.unsafeRunSync() mustBe true
    }

    it should "not verify for a wrong key pair" in {
      val expression: IO[Boolean] = for {
        keyPair1 <- F.fromEither[SigKeyPair[A]](ecKFTag.generateKeyPair)
        keyPair2 <- F.fromEither[SigKeyPair[A]](ecKFTag.generateKeyPair)
        signed   <- interp.sign(toSign, keyPair1.privateKey)
        verify   <- interp.verify(toSign, signed, keyPair2.publicKey)
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
