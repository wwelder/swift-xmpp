# SwiftXMPP

A small XMPP client core for Apple platforms, written from the specifications.

No dependencies. Roughly a thousand lines. It connects, secures the stream,
authenticates with SCRAM, binds a resource, and tells you what the server can
do — which is everything a client needs before it starts being a client.

```swift
let session = XMPPSession()
let capabilities = try await session.connect(
    jid: JID("you@example.org")!,
    password: password
)

// What the server said it supports, not what we assumed about it.
capabilities.saslMechanisms   // ["SCRAM-SHA-256", "SCRAM-SHA-1", …]
capabilities.features         // disco#info
capabilities.services         // disco#items
```

## What it does

| | |
|---|---|
| RFC 6120 | stream negotiation, STARTTLS, SASL, resource binding |
| RFC 5802 / 7677 | SCRAM-SHA-1 and SCRAM-SHA-256, with the official test vectors |
| XEP-0030 | service discovery |
| XEP-0198 | stream management, with resumption after a dropped connection |
| XEP-0280 | message carbons |
| XEP-0352 | client state indication |
| XEP-0357 | push registration (the client's half) |

STARTTLS is why the transport uses CFStream rather than Network.framework:
`NWConnection` fixes its security parameters at creation and cannot upgrade a
live plaintext connection, and that upgrade is what nearly every server offers
on port 5222.

## What it does not do yet

Message archives (XEP-0313) are not implemented. OMEMO (XEP-0384) is in
progress, and deserves a word about how.

End-to-end encryption is not a thing to implement casually, and none of the
primitives here are ours: X25519, Ed25519, HKDF, HMAC and AES all come from
CryptoKit. What CryptoKit lacks is XEdDSA — signing with the same Curve25519
key used for agreement, which OMEMO requires — and the map between the curve's
Montgomery and Edwards forms that XEdDSA is built on. The map is about a
hundred lines of field arithmetic in `OMEMO/FieldElement.swift`. It only ever
touches other people's public keys, never a secret, and it is checked against
CryptoKit itself: the same scalar produces the same point in both forms, and
the conversion has to agree bit for bit on hundreds of random keys before the
tests pass. Our own private keys never leave CryptoKit.

The protocol above that — X3DH, the Double Ratchet, and OMEMO's framing — is
written from the published Signal specifications and the XEP. It is not done
until it has exchanged messages with an existing OMEMO client, and the tests
say so.

## Two decisions worth knowing about

**The server is authenticated too.** SCRAM is mutual: after the exchange the
client verifies the server's signature, and a peer that cannot produce it is
rejected. Skipping that check is the classic SCRAM implementation bug, because
everything still appears to work — logins succeed against real servers, and the
mutual half is silently gone.

**Certificates are validated.** A client that talks to servers run by strangers
has to verify them; accepting any certificate exposes the SASL exchange to
anyone on the path. Pinning is supported for the self-hosted case, where a
private CA is normal, and is explicit rather than a blanket opt-out.

## Provenance

Written from RFC 6120, RFC 6121, RFC 5802, RFC 7677 and the XEP documents. Not
derived from any existing implementation. The protocol is a public
specification and always was; this exists because the good XMPP libraries for
Apple platforms are copyleft, their App Store builds are shipped by their own
copyright holders, and a third party cannot follow them there.

## Licence

AGPL-3.0. See `LICENSE`.

If you want it under other terms, ask — but understand the mechanism first: the
project can only offer you a different licence while its copyright stays in one
place. Contributions are accepted under a CLA for exactly that reason. A
codebase that accumulates contributions without one can never be relicensed
again, including by the people who started it.
