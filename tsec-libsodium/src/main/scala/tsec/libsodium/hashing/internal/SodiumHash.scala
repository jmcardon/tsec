package tsec.libsodium.hashing.internal

import tsec.libsodium.ScalaSodium
import tsec.libsodium.hashing.HashState

trait SodiumHash[A] {

  val hashLen: Int

  val algorithm: String

  def stateSize(implicit S: ScalaSodium): Int

  def sodiumHash(in: Array[Byte], out: Array[Byte])(implicit S: ScalaSodium): Int

  def sodiumHashInit(state: HashState[A])(implicit S: ScalaSodium): Int

  def sodiumHashChunk(state: HashState[A], in: Array[Byte])(implicit S: ScalaSodium): Int

  def sodiumHashFinal(state: HashState[A], out: Array[Byte])(implicit S: ScalaSodium): Int

}
