package tsec.cipher.symmetric

import tsec.common.{ArrayHKNewt, ArrayNewt}

package object libsodium {

  /** Our newtype over private keys **/
  type SodiumKey[A] = SodiumKey.Type[A]

  object SodiumKey extends ArrayHKNewt

  type CryptoStreamHeader = CryptoStreamHeader.Type

  object CryptoStreamHeader extends ArrayNewt

  private[tsec] type CryptoStreamState = CryptoStreamState.Type

  object CryptoStreamState extends ArrayNewt
}
