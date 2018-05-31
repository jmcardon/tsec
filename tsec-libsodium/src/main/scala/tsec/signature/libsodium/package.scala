package tsec.signature

import tsec.common.ArrayHKNewt

package object libsodium {

  type RawMessage[A] = RawMessage.Type[A]

  object RawMessage extends ArrayHKNewt

  type SignedMessage[A] = SignedMessage.Type[A]

  object SignedMessage extends ArrayHKNewt

  type PrivateKey[A] = PrivateKey.Type[A]

  //Todo: Check keyLen for building.
  object PrivateKey extends ArrayHKNewt

  type PublicKey[A] = PublicKey.Type[A]

  object PublicKey extends ArrayHKNewt

  final case class SodiumKeyPair[A](pubKey: PublicKey[A], privKey: PrivateKey[A])

}
