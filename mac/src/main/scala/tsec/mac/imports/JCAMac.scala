package tsec.mac.imports

import java.security.MessageDigest
import java.util.concurrent.{ConcurrentLinkedQueue => JQueue}
import javax.crypto.Mac

import cats.effect.Sync
import cats.syntax.all._
import tsec.mac.core._

abstract class JCAMac[A](tl: JQueue[Mac])(implicit macTag: JCAMacTag[A]) {

  private def genInstance[F[_]](implicit F: Sync[F]): F[Mac] = F.delay {
    val inst: Mac = tl.poll()
    if (inst != null)
      inst
    else
      Mac.getInstance(macTag.algorithm)
  }

  def sign[F[_]](content: Array[Byte], key: MacSigningKey[A])(implicit F: Sync[F]): F[MAC[A]] =
    for {
      instance <- genInstance[F]
      _        <- F.delay(instance.init(MacSigningKey.toJavaKey[A](key)))
      fin      <- F.delay(instance.doFinal(content))
      _        <- F.delay(tl.add(instance))
    } yield MAC[A](fin)

  def verify[F[_]: Sync](toSign: Array[Byte], signed: MAC[A], key: MacSigningKey[A]): F[Boolean] =
    sign[F](toSign, key).map(MessageDigest.isEqual(signed, _))

  @deprecated("Please use verify, using the newtypes. This version will be removed", "0.0.1-M10")
  final def verifyArrays[F[_]: Sync](toSign: Array[Byte], signed: Array[Byte], key: MacSigningKey[A]): F[Boolean] =
    sign[F](toSign, key).map(MessageDigest.isEqual(signed, _))

}

object JCAMac {
  def apply[A](numInstances: Int = 10)(implicit tag: JCAMacTag[A]): JCAMac[A] = {
    val queue = new JQueue[Mac]()
    var i     = 0
    while (i < numInstances) {
      queue.add(Mac.getInstance(tag.algorithm))
      i += 1
    }
    new JCAMac[A](queue) {}
  }

  implicit def gen[A: JCAMacTag]: JCAMac[A] = apply[A]()
}
