package tsec.jws.algorithms

import tsec.mac.instance._
import tsec.mac.core.MacPrograms
import tsec.signature.core.{SignatureAlgorithm, SignerDSL}
import tsec.signature.instance.{SHA256withECDSA, SHA384withECDSA, SHA512withECDSA}



sealed trait JWTAlgorithm[A] {
  val jwtRepr: String

}

object JWTAlgorithm {
  implicit case object HS256 extends JWTMacAlgo[HMACSHA256]{
    val jwtRepr: String = "HS256"
  }

  implicit case object HS384 extends JWTMacAlgo[HMACSHA384]{
    val jwtRepr: String = "HS384"
  }

  implicit case object HS512 extends JWTMacAlgo[HMACSHA512]{
    val jwtRepr: String = "HS512"
  }

  implicit case object NoAlg extends JWTAlgorithm[NoSigningAlgorithm]{
    val jwtRepr: String = "none"
  }

  /**
   * Currently not compiling, needs fix
   */

  implicit case object ES256 extends JWTSigAlgo[SHA256withECDSA]{
    val jwtRepr: String = "ES256"
  }

  implicit case object ES384 extends JWTSigAlgo[SHA384withECDSA]{
    val jwtRepr: String = "ES384"
  }

  implicit case object ES512 extends JWTSigAlgo[SHA512withECDSA]{
    val jwtRepr: String = "ES512"
  }

}

abstract class JWTMacAlgo[A: MacTag](implicit gen: MacPrograms.MacAux[A]) extends JWTAlgorithm[A]

abstract class JWTSigAlgo[A: SignatureAlgorithm](implicit gen: SignerDSL.Aux[A]) extends JWTAlgorithm[A]

object JWTMacAlgo {
  def fromString[A](alg: String)(implicit o: JWTMacAlgo[A]): Option[JWTMacAlgo[A]] = alg match {
    case o.jwtRepr => Some(o)
    //While we work on signatures, this can be none.
    case _ => None
  }
}