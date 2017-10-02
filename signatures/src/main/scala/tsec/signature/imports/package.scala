package tsec.signature

package object imports {
  type SigErrorM[A] = Either[Throwable, A]
}
