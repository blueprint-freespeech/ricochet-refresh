# Ricochet-Refresh v3.0.X Configuration Specification

#### Morgan <[morgan@blueprintforfreespeech.net](mailto:morgan@blueprintforfreespeech.net)>

---

## Introduction

Ricochet-Refresh is a peer-to-peer instant messaging application built on Tor onion-services. This document describes the format of the `ricochet.json` configuration file used in the Ricochet-Refresh 3.0.X series.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119[^1].

## Overview

This document defines the JSON structure, types, defaults, validation rules, and semantics for the settings file used by Ricochet-Refresh v3.0.X series. Implementations MUST parse and validate against the rules below.

By default, the config file is located in the following locations based on host operating system:

- **Windows** `%USERPROFILE%/AppData/Local/ricochet-refresh/ricochet.json`
- **macOS** `~/Library/Preferences/ricochet-refresh/ricochet.json`
- **Linux** `~/.config/ricochet-refresh/ricochet.json`

## File format

- The file MUST be UTF-8 encoded JSON[^2].
- The top-level value MUST be a JSON object.
- Unless otherwise specified, any unknown fields MUST be ignored when reading but MAY not be discarded when writing.


## Top-level object

Top-level object MAY contain the following members:
- `identity` : object
    - Purpose: material required to 'login' to Ricochet-Refresh as a particular user
    - Presence: OPTIONAL.
    - Fields:
        - `privateKey` : string
          - MUST be present if `identity` is present.
          - Format: An ed25519 private key in the legacy c-tor daemon key blog format used in the `ADD_ONION` control-port command[^3]
          - Implementations MUST reject values which are not valid ed25519 private keys.
          - The value MAY be empty, in which case, implementations MUST securely generate a new key; otherwise it MUST be a valid key.
    - Unknown fields in `identity` SHOULD be ignored.

- `tor` : object
    - Purpose: configuration settings required to connect to the Tor network
    - Presence: OPTIONAL.
    - Fields:
        - `allowedPorts` : number[]
            - Presence: OPTIONAL
            - Format: Each item MUST be integers in range 1..65535.
            - Duplicates SHOULD be ignored by consumers.
            - If omitted, consumers MUST assume no explicit allowed ports (i.e. all ports are available).
        - `bridgeType`: string
            - Presence: OPTIONAL
            - Allowed values: "obfs4", "meek", "meek-azure", "snowflake", "custom", "none"
            - If present and non-empty, consumers MUST validate against supported bridge types and reject unknown values.
            - If absent, consumers MUST assume a value of "none"
        - `bridgeStrings` : string[]
            - Presence: REQUIRED and MUST NOT be empty if `bridgeType` is "custom"
            - Format: Each item MUST be a valid bridge string[^4]
            - Duplicates SHOULD be ignored by consumers.
        - `seed` : number
            - Presence: OPTIONAL
            - Format: MUST be a valid 32-bit unsigned integer
            - If not present or not a valid 32-bit unsigned integer, a new random 32-bit unsigned integer MUST be generated
        - `proxy` : object
            - Presence: OPTIONAL
            - Fields:
                - `type` : string
                    - Presence: REQUIRED
                    - Allowed values: "socks4", "socks5", "https"
                - `address` : string
                    - Presence: REQUIRED
                    - Format: MUST be an IP address or DNS name.
                - `port` : number
                    - Presence: REQUIRED
                    - MUST be in range 1..65535
                - `username` : string
                    - Presence: OPTIONAL
                    - MAY be empty.
                    - MUST be ignored if `type` is "socks4"
                - `password` : string
                    - MAY be empty.
                    - MUST be ignored if `type` is "socks4"
            - Unknown fields in `proxy` SHOULD be ignored.
    - Unknown fields in `tor` SHOULD be ignored.
- `ui` : object
    - Purpose: settings related to the application's user-interface
    - Presence: OPTIONAL
    - Fields:
        - `combinedChatWindow` : boolean
            - Presence: OPTIONAL
            - If omitted, defaults to false
        - `language` : string
            - Presence: OPTiONAL
            - MUST be one of: "", "bg", "cs", "de", "en", "es", "et_EE", "fi", "fil_PH", "fr", "he", "it", "it_IT", "ja", "nb", "nl_NL", "pl" "pt_BR", "pt_PT", "ru", "sl", "sq", "sv", "tr", "uk", "zh", or "zh_HK"
            - If omitted, defaults to empty string which is interpreted as the system or default language
        - `notificationVolume` : number
            - Presence: OPTiONAL
            - MUST be in range 0.0..1.0
            - If omitted, defaults to 0.75
        - `playAudioNotification` : boolean
            - Presence: OPTiONAL
            - If omitted, defaults to false
            - If Default: false if omitted.
    - Unknown fields in `ui` SHOULD be ignored.
- `users` : objects
    - Purpose: the set of users known to the profile owner and associated data
    - Presence: OPTIONAL
    - Each key for the fields on this object MUST be valid base32-encoded v3 onion-service id
    - Fields:
        - `/[a-z2-7]{56}/` : object
            - Fields:
                - `nickname` : string
                    - Presence: REQUIRED
                - `type` : string
                    - MUST be one of:
                        - "allowed" : users in the profile owners's contact list
                        - "requesting" : users who have added profile owner's but the profile owners has not replied to yet
                        - "blocked" : users the profile owner's has blocked and wishes to ignore
                        - "pending" : users the profile owner's has added but have not replied yet
                        - "rejected" : users the profile owner's has added but have replied with rejection
    - Unknown fields in `users` SHOULD be ignored

---

[^1]: RFC 2119 [https://www.rfc-editor.org/rfc/rfc2119](https://www.rfc-editor.org/rfc/rfc2119)

[^2]: JSON specification [https://json.org](https://json.org)

[^3]: ADD_ONION specification: [https://spec.torproject.org/control-spec/commands.html#add_onion](https://spec.torproject.org/control-spec/commands.html#add_onion)

[^4]: Bridge line format: [https://tpo.pages.torproject.net/core/doc/rust/tor_guardmgr/bridge/struct.BridgeConfig.html#string-representation](https://tpo.pages.torproject.net/core/doc/rust/tor_guardmgr/bridge/struct.BridgeConfig.html#string-representation)
