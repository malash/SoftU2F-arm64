//
//  KeyPair.swift
//  SoftU2F
//
//  Created by Benjamin P Toews on 2/2/17.
//

import Foundation

class KeyPair {
    // Fix up legacy keychain items.
    static func repair(label: String) {
        // useless
    }

    /// Get all KeyPairs with the given label.
    static func all(label: String) -> [KeyPair] {
        let applicationLabels = KeychainLocal.listAllApplicationLabels()
        var keyPairs: [KeyPair] = []

        applicationLabels.forEach { applicationLabel in
            if let kp = KeyPair(label: label, appLabel: applicationLabel, signPrompt: "opration from CLI") {
                keyPairs.append(kp)
            }
        }

        return keyPairs
    }

    // The number of private keys in the keychain.
    static func count(label: String) -> Int? {
        return KeychainLocal.listAllApplicationLabels().count
    }

    // Delete all keys with the given label from the keychain.
    static func delete(label: String) -> Bool {
        KeyPair.all(label: label).forEach { kp in
            _ = kp.delete()
        }
        return true
    }

    let label: String
    let applicationLabel: Data
    let signPrompt: String

    // Application tag is an attribute we use to smuggle data.
    var applicationTag: Data? {
        get {
            return KeychainLocal.getApplicationTag(applicationLabel: applicationLabel)
        }

        set {
            KeychainLocal.setApplicationTag(applicationLabel: applicationLabel, applicationTag: (newValue ?? Data()))
        }
    }

    var publicKeyData: Data? {
        return KeychainLocal.exportPublicKey(applicationLabel: applicationLabel)
    }

    var inSEP: Bool {
        return false
    }

    // Generate a new key pair.
    init?(label l: String, inSEP sep: Bool) {
        label = l
        applicationLabel = KeychainLocal.generateKeyPair(attrLabel: label as CFString)
        signPrompt = "initial"
        KeychainLocal.log(applicationLabel: applicationLabel, signPrompt: signPrompt, message: "KeyPair created")
    }

    // Find a key pair with the given label and application label.
    init?(label l: String, appLabel al: Data, signPrompt sp: String) {
        label = l
        applicationLabel = al
        signPrompt = sp
        KeychainLocal.log(applicationLabel: applicationLabel, signPrompt: signPrompt, message: "KeyPair found")
    }

    // Delete this key pair.
    func delete() -> Bool {
        KeychainLocal.log(applicationLabel: applicationLabel, signPrompt: signPrompt, message: "KeyPair removed")
        return KeychainLocal.delete(applicationLabel: applicationLabel)
    }

    // Sign some data with the private key.
    func sign(_ data: Data) -> Data? {
        KeychainLocal.log(applicationLabel: applicationLabel, signPrompt: signPrompt, message: "KeyPair sgined")
        return KeychainLocal.sign(applicationLabel: applicationLabel, data: data)
    }

    // Verify some signature over some data with the public key.
    func verify(data: Data, signature: Data) -> Bool {
        // useless
        return false
    }
}
