//
//  KeychainLocal.swift
//  SoftU2F
//
//  Created by Malash on 8/31/22.
//  Copyright © 2022 GitHub. All rights reserved.
//

import Foundation

@discardableResult
func safeShell(_ command: String) throws -> String {
    let task = Process()
    let pipe = Pipe()

    task.standardOutput = pipe
    task.standardError = pipe
    task.arguments = ["-c", command]
    task.executableURL = URL(fileURLWithPath: "/bin/zsh") //<--updated
    task.standardInput = nil

    try task.run() //<--updated

    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    let output = String(data: data, encoding: .utf8)!

    return output
}

extension StringProtocol {
    var hexaData: Data { .init(hexa) }
    var hexaBytes: [UInt8] { .init(hexa) }
    private var hexa: UnfoldSequence<UInt8, Index> {
        sequence(state: startIndex) { startIndex in
            guard startIndex < self.endIndex else { return nil }
            let endIndex = self.index(startIndex, offsetBy: 2, limitedBy: self.endIndex) ?? self.endIndex
            defer { startIndex = endIndex }
            return UInt8(self[startIndex..<endIndex], radix: 16)
        }
    }
}

extension UInt32 {
    var data: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<UInt32>.size)
    }
}

extension Data {
    var hexDescription: String {
        return reduce("") {$0 + String(format: "%02x", $1)}
    }
}

extension Date {
    static func ISOStringFromDate(date: Date) -> String {
        let dateFormatter = DateFormatter()
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        dateFormatter.timeZone = TimeZone(abbreviation: "GMT")
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
        
        return dateFormatter.string(from: date).appending("Z")
    }
    
    static func dateFromISOString(string: String) -> Date? {
        let dateFormatter = DateFormatter()
        dateFormatter.locale = Locale(identifier: "en_US_POSIX")
        dateFormatter.timeZone = TimeZone.autoupdatingCurrent
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
        
        return dateFormatter.date(from: string)
    }
}

class KeychainLocal {
    static var dataDir = NSString(string: "~/.SoftU2F").expandingTildeInPath
    static var keysDir = dataDir + "/keys"
    static var logDir = dataDir + "/logs"

    private class KeychainFileNames {
        let applicationLabel: String

        init(label: Data) {
            applicationLabel = label.hexDescription
        }

        var privateKeyFileName: String {
            get {
                return KeychainLocal.keysDir + "/" + applicationLabel + ".key"
            }
        }
        var publicKeyFileName: String {
            get {
                return KeychainLocal.keysDir + "/" + applicationLabel + ".crt"
            }
        }
        var applicationTagFileName: String {
            get {
                return KeychainLocal.keysDir + "/" + applicationLabel + ".tag"
            }
        }
    }

    private static func labelToFileNames(label: Data) -> (String, String, String) {
        let applicationLabel = label.hexDescription
        let privateKeyFileName = KeychainLocal.keysDir + "/" + applicationLabel + ".key"
        let publicKeyFileName = KeychainLocal.keysDir + "/" + applicationLabel + ".crt"
        let applicationTagFileName = KeychainLocal.keysDir + "/" + applicationLabel + ".tag"
        return (privateKeyFileName, publicKeyFileName, applicationTagFileName)
    }

    static func generateKeyPair(attrLabel: CFString) -> Data {
        var applicationLabelData = Data(capacity: 20)
        for _ in 1...5 {
            applicationLabelData.append(arc4random().data)
        }
        let names = KeychainFileNames(label: applicationLabelData)
        _ = try? safeShell("mkdir -p " + KeychainLocal.keysDir)
        _ = try? safeShell("openssl ecparam -name prime256v1 -genkey -noout -out " + names.privateKeyFileName)
        _ = try? safeShell("openssl ec -in " + names.privateKeyFileName + " -pubout -out " + names.publicKeyFileName)

        return applicationLabelData
    }

    static func exportPublicKey(applicationLabel: Data) -> Data? {
        let names = KeychainFileNames(label: applicationLabel)
        guard let publicKeyEncoded = try? safeShell("sed '1d; $d' " + names.publicKeyFileName + " | tr -d '\n'") else { return nil }
        guard let publicKey = Data(base64Encoded: publicKeyEncoded) else { return nil }
        return publicKey.subdata(in: 26..<publicKey.count)
    }

    static func setApplicationTag(applicationLabel: Data, applicationTag: Data) {
        let names = KeychainFileNames(label: applicationLabel)
        let applicationTagEncoded = applicationTag.base64EncodedString()
        _ = try! applicationTagEncoded.write(to: URL(fileURLWithPath: names.applicationTagFileName, isDirectory: false), atomically: true, encoding: String.Encoding.utf8)
    }

    static func getApplicationTag(applicationLabel: Data) -> Data? {
        let names = KeychainFileNames(label: applicationLabel)
        guard let applicationTagEncoded = try? String(contentsOfFile: names.applicationTagFileName) else { return nil }
        return Data(base64Encoded: applicationTagEncoded)
    }

    static func listAllApplicationLabels() -> [Data] {
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: keysDir) else { return [] }
        return files.filter { file in
            file.hasSuffix(".tag")
        }.map { file in
            (file as NSString).deletingPathExtension
        }.map { file in
            file.hexaData
        }
    }
    
    static func delete(applicationLabel: Data) -> Bool {
        let names = KeychainFileNames(label: applicationLabel)
        _ = try? FileManager.default.removeItem(at: URL(fileURLWithPath: names.privateKeyFileName))
        _ = try? FileManager.default.removeItem(at: URL(fileURLWithPath: names.publicKeyFileName))
        _ = try? FileManager.default.removeItem(at: URL(fileURLWithPath: names.applicationTagFileName))
        return true
    }

    static func sign(applicationLabel: Data, data: Data) -> Data? {
        let names = KeychainFileNames(label: applicationLabel)
        let dataEncoded = data.base64EncodedString()
        guard let signed = try? safeShell("echo \"" + dataEncoded + "\" | openssl base64 -d -A | openssl dgst -sha256 -sign " + names.privateKeyFileName + " | openssl base64 -a") else {
            return nil
        }
        let result = Data(base64Encoded: signed, options: [.ignoreUnknownCharacters])
        return result
    }
    
    static func log(applicationLabel: Data, signPrompt: String?, message: String) {
        let fileName = logDir + "/softu2f.log"
        var logLine = ""
        logLine += "[" + Date.ISOStringFromDate(date: Date()) + "] "
        logLine += "{" + applicationLabel.hexDescription + "} "
        logLine += "<" + (signPrompt ?? "unknown") + "> "
        logLine += message
        _ = try? safeShell("mkdir -p " + logDir)
        _ = try? safeShell("echo \"" + logLine + "\" >> " + fileName)
    }
}
