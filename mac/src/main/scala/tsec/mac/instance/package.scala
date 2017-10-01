package tsec.mac

package object instance {

  type MacErrorM[A] = Either[MacError, A]

}
