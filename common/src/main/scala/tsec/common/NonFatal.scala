package tsec.common

private[tsec] object NonFatal {

  def apply(t: Throwable): Boolean = t match {
    case _: VirtualMachineError => false
    case _                      => true
  }

  def unapply(t: Throwable): Option[Throwable] =
    if (apply(t)) Some(t) else None
}
