package tsec.cipher.asymmetric

import tsec.common.ArrayHKNewt

package object libsodium {

  type PrivateKey[A] = PrivateKey.Type[A]

  //Todo: Check keyLen for building.
  object PrivateKey extends ArrayHKNewt

  type PublicKey[A] = PublicKey.Type[A]

  object PublicKey extends ArrayHKNewt

  final case class SodiumKeyPair[A](pubKey: PublicKey[A], privKey: PrivateKey[A])

  type PKAuthTag[A] = PKAuthTag.Type[A]

  object PKAuthTag extends ArrayHKNewt

  type SharedKey[A] = SharedKey.Type[A]

  object SharedKey extends ArrayHKNewt

}
