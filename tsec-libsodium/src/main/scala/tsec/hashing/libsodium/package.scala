package tsec.hashing

import tsec.common.{ArrayHKNewt, ArrayNewt}

package object libsodium {
  type HashState[A] = HashState.Type[A]

  object HashState extends ArrayHKNewt

  type BlakeKey = BlakeKey.Type

  object BlakeKey extends ArrayNewt
}
