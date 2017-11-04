package tsec.csrf

import cats.effect.Sync
import tsec.common.ByteEV
import tsec.mac.imports.{JCAMacPure, MacTag}

/** A CSRF Token Signer, adapted from:
  * https://github.com/playframework/playframework/blob/master/framework/src/play/src/main/scala/play/api/libs/crypto/CSRFTokenSigner.scala
  * by Will Sargent, to use the tsec crypto primitives
  *
  */
sealed abstract class CSRFTokenSigner[F[_]: Sync, A: MacTag: ByteEV](token: CSRFToken, headerName: String)(implicit mac: JCAMacPure[F, A]) {

//  def checkAndSign(token: CSRFToken) = {
//    token.split("-") match {
//      case Array(token:)
//
//    }
//
//  }

}
