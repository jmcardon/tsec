package tsec.kdf

import tsec.common.ArrayNewt

package object libsodium {

  //Todo: Good application for refined
  type MasterKey = MasterKey.Type

  //Todo: Check keyLen for building.
  object MasterKey extends ArrayNewt

  //Todo: Good application for refined
  type DerivedKey = DerivedKey.Type

  //Todo: Check keyLen for building.
  object DerivedKey extends ArrayNewt

}
