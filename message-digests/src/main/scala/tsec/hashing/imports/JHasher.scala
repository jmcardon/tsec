package tsec.hashing.imports

//import cats.data.NonEmptyList
//import tsec.hashing.CryptoPickler
//import tsec.hashing.core._

//class JHasher[T: JCADigestTag](
//    algebra: JHashAlgebra[T]
//) extends HashingPrograms[T](algebra)
//
//object JHasher {
//
//  def apply[T: JCADigestTag] = new JHasher[T](new JHashAlgebra[T])
//
//  implicit def genHasher[T: JCADigestTag]: JHasher[T] = apply[T]
//
//  def hash[C, T](toHash: C)(implicit cryptoPickler: CryptoPickler[C], hasher: JHasher[T]): CryptoHash[T] =
//    hasher.hash[C](toHash)
//
//  def hashBytes[T](bytes: Array[Byte])(implicit hasher: JHasher[T]): CryptoHash[T] =
//    hasher.hashBytes(bytes)
//
//  def hashToByteArray[T](bytes: Array[Byte])(implicit hasher: JHasher[T]): Array[Byte] =
//    hasher.hashToByteArray(bytes)
//
//  def combineAndHash[C, T](
//      toHash: NonEmptyList[C]
//  )(implicit cryptoPickler: CryptoPickler[C], hasher: JHasher[T]): CryptoHash[T] =
//    hasher.combineAndHash[C](toHash)
//
//}
