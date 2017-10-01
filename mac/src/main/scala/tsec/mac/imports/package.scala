package tsec.mac

package object imports {

  type MacErrorM[A] = Either[MacError, A]

}
