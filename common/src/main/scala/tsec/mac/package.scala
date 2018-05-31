package tsec

import tsec.common.ArrayHKNewt

package object mac {

  type MAC[A] = MAC.Type[A]

  object MAC extends ArrayHKNewt

}
