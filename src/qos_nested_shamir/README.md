# `qos_nested_shamir`

A 64-byte secret dealt down a nested threshold tree of holders with Shamir over
GF(2^8), and rebuilt bottom up against its SHA3-384 root commitment. A point is
satisfied once its threshold of children are; each leaf is a holder named by the
digests of its receiving and signing keys. Point hints let a rebuild pass over a
bad shard, and only a secret matching the root commitment is accepted.

Copied from Umbra's `umbra-nested-shamir`, which the guardian share nodes deal
their root with; the domain labels are unchanged, so both produce the same
deals, hints and commitments.
