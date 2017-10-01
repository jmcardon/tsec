package tsec.signature

package object instance {
  type SigErrorM[A] = Either[Throwable, A]
}
