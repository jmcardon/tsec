package tsec.mac.libsodium

import tsec.libsodium.ScalaSodium
import tsec.mac._

trait SodiumMacAlgo[A] {
  val keyLen: Int
  val macLen: Int
  val algorithm: String

  private[tsec] def sodiumSign(in: Array[Byte], out: Array[Byte], key: SodiumMACKey[A])(implicit S: ScalaSodium): Int

  private[tsec] def sodiumVerify(in: Array[Byte], hashed: MAC[A], key: SodiumMACKey[A])(
      implicit S: ScalaSodium
  ): Int

}
