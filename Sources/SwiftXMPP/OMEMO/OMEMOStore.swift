//
// SwiftXMPP — an XMPP client core written from the specifications.
// Copyright (C) 2026 Baseco.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details. You should have received a copy of it in the LICENSE file.
//

import Foundation

/// Where a client keeps its OMEMO identity between launches.
///
/// The identity seed is a private key and belongs in the Keychain, not in
/// UserDefaults; the device id is not secret but is kept alongside it so the
/// two cannot drift apart. Deliberately the caller's job, because how a device
/// stores secrets is policy the library should not dictate - and a client that
/// loses this becomes a new, unverified device to everyone it talks to.
public protocol OMEMOKeyStore: AnyObject {
    func loadIdentity() -> (identity: IdentityKey, deviceID: UInt32)?
    func saveIdentity(seed: Data, deviceID: UInt32)
}

/// Answers the engine's bundle requests by fetching from PEP through the live
/// session. This is the seam between the transport-free engine and the wire.
final class PEPBundleSource: OMEMOBundleSource {
    private weak var session: XMPPSession?
    init(session: XMPPSession) { self.session = session }

    func bundle(for jid: String, deviceID: UInt32) async throws -> OMEMOBundle {
        guard let session else { throw OMEMOError.malformedMessage }
        return try await session.fetchBundle(for: jid, deviceID: deviceID)
    }

    func deviceIDs(for jid: String) async throws -> [UInt32] {
        guard let session else { throw OMEMOError.malformedMessage }
        return try await session.fetchDeviceList(for: jid)
    }
}
