---
layout: home
title:  "Philosophy"
section: "crypto"
position: 4
---

## Philosophy

TSec aims to be a Functional-first library. This means we aim to provide defaults for functional programming,
and methods that are side effecting and otherwise not referentially transparent (without suspension into 
some sort of monad that captures effects) will have `unsafe` in their name, and the objects you use to access them 
as `Impure`.

This does not mean that we aim to make it impossible to use in a non-functional context, but rather
that we make an effort to point out that some operation is side effecting and may throw an exception
if it is not captured (or interpreted into some `Either[Throwable, _]`).

TSec aims to bring principled security to the Scala community. This means starting from the primitives, and working
our way up to more complicated efforts. This means that this effort aims to expand over
just the basic building blocks, and eventually grow into more complicated protocols and cryptographic
applications wherever it is fit to do so on the JVM, such as OAuth, Key Distribution servers and more.

We aim to provide secure defaults wherever possible, and enable the most principled 
security work we can. Also, wherever nice abstraction conflicts with performance,
we will always choose performance over abstraction in a way that will not affect the API, only
how the method is coded. Ugly code for us = good. Ugly code for you = bad.

TSec is not a one-person effort, it is a community effort. I(Jose)/We thank all contributors, maintainers
and members of the community that have helped out in trying to craft this project!