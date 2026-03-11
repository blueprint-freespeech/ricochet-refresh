# Ricochet-Refresh v4.0.X Profile Specification

### version 0.1.0

#### Morgan <[morgan@blueprintforfreespeech.net](mailto:morgan@blueprintforfreespeech.net)>

---

## Introduction

Ricochet-Refresh is a peer-to-peer instant messaging application built on Tor onion-services. This document describes an encrypted file-format used for storing a user profile.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119[^1].

## Overview

The Ricochet-Refresh profile file format uses an encrypted SQLite database (SQLCipher) to store user profile information. This format includes multiple tables designed to hold different types of user-related data such as contacts and messaging history.

The specification will outline the structure of each table, including data types and constraints. It is presumed that all tables have an implicit `rowid` column which is a unique, auto-incrementing integer.

For the various payload calculations, the `+` operator indicates concatenation with a null byte in-between.

## Tables

### `db_versions`

This table stores the current semantic versions[^2] of this database. The profile's version must be stored in the row with the largest `rowid` value.

#### Schema
| Name | Type | Constraints |
| ---- | ---- | ----------- |
| major | INTEGER | NOT NULL CHECK(major >= 0) |
| minor | INTEGER | NOT NULL CHECK(minor >= 0) |
| patch | INTEGER | NOT NULL CHECK(patch >= 0) |

#### Members
- **major** : the semantic major version
- **minor** : the semantic minor version
- **patch** : the semantic patch version

### `user_profiles`

A table of user profiles, each associated with a particular user.

#### Schema
| Name | Type | Constraints |
| ---- | ---- | ----------- |
| nickname | TEXT | NOT NULL |
| pet_name | TEXT | UNIQUE |
| pronouns | TEXT | CHECK(LENGTH(pronouns) <= 64) |
| avatar_rowid | INTEGER | UNIQUE REFERENCES avatars(rowid) |
| status | TEXT | CHECK(LENGTH(status) <= 256) |
| description | TEXT | CHECK(LENGTH(description) <= 2048) |

#### Members
- **nickname** : the user's chosen display name
- **pet_name** : the name the local owner has assigned to this user
- **pronouns** : the user's optional chosen pronouns
- **avatar_rowid** : the optional `rowid` of the `avatar` associated with this user profile
- **status** : the user's optional chosen status
- **description** : the user's optional chosen description

### `avatars`

A table of user avatars.

#### Schema
| Name | Type | Constraints |
| ---- | ---- | ----------- |
| value | BLOB | CHECK(LENGTH(value) = 262144) |

#### Members

- **value** : an image stored as 256x256 array of 8-bit/channel RGBA pixels in row-major order

### `users`

A table of all our users.

#### Schema
| Name | Type | Constraints |
| ---- | ---- | ----------- |
| user_type | INTEGER | NOT NULL CHECK(user_type >= 0 AND user_type <= 4) |
| user_profile_rowid | INTEGER | NOT NULL UNIQUE REFERENCES user_profiles(rowid) |
| identity_ed25519_public_key_rowid | INTEGER | NOT NULL UNIQUE REFERENCES ed25519_public_keys(rowid) |
| identity_ed25519_private_key_rowid | INTEGER | UNIQUE REFERENCES ed25519_private_keys(rowid) |
| remote_endpoint_ed25519_public_key_rowid | INTEGER | UNIQUE REFERENCES ed25519_public_keys(rowid) |
| remote_endpoint_x25519_private_key_rowid | INTEGER | UNIQUE REFERENCES x25519_private_keys(rowid) |
| local_endpoint_ed25519_private_key_rowid | INTEGER | UNIQUE REFERENCES ed25519_private_keys(rowid) |
| local_endpoint_x25519_public_key_rowid | INTEGER | UNIQUE REFERENCES x25519_public_keys(rowid) |
| | | CHECK((user_type = 0) = (identity_ed25519_private_key_rowid IS NOT NULL)) |
| | | CHECK(remote_endpoint_ed25519_public_key_rowid IS NULL = remote_endpoint_x25519_private_key_rowid IS NULL) |
| | | CHECK(local_endpoint_ed25519_private_key_rowid IS NULL = local_endpoint_x25519_public_key_rowid IS NULL) |

#### Members
- **user_type** : an enum identifying this user's type; MUST be one of:
    - Owner(0) : the local owner of this profile; there MUST be only 1 row with this value
    - Allowed(1) : a remote user the owner has allowed access
    - Requesting(2) : a remote user that is requesting access from the owner
    - Rejected(3) : a remote user that has rejected the owner's request for access
    - Blocked(4) : a remote user that the owner has permanently rejected
- **user_profile_rowid** : the `rowid` of the `profile` associated with this user
- **identity_ed25519_public_key_rowid** : the `rowid` of the `ed25519_public_key` for the identity onion service associated with this user
- **identity_ed25519_private_key_rowid** : the `rowid` of the `ed25519_private_key` for the identity onion service the user hosts; MUST be NULL if `user_type` is anything other than `0` (Owner)
- **remote_endpoint_ed25519_public_key_rowid** : the `rowid` of the `ed25519_public_key` for the endpoint onion service the remote user hosts
- **remote_endpoint_x25519_private_key_rowid** : the `rowid` of the `x25519_private_key` the owner uses to decrypt the service descriptor of the endpoint onion service hosted by the remote user
- **local_endpoint_ed25519_private_key_rowid** : the `rowid` of the `ed25519_private_key` the owner uses to host the endpoint onion service the remote user connects to
- **local_endpoint_x25519_public_key_rowid** : the `rowid` of the `x25519_public_key` the owner uses to encrypt the service descriptor of the endpoint onion service the remote user connects to

### `conversations`

A table of all conversations.

#### Schema
| Name | Type | Constraints |
| ---- | ---- | ----------- |
| conversation_type | INTEGER | NOT NULL CHECK(conversation_type >= 1 AND conversation_type <= 2) |
| conversation_key_rowid | INTEGER | NOT NULL UNIQUE REFERENCES sha256_hashes(rowid) |

#### Members
- **conversation_type** : the enum identifying this `conversation`'s type; MUST be one of:
    - PersistentDirectMessage (1) : a persistent `conversation` with a single `user`
    - EphemeralDirectMessage (2) : an ephemeral `conversation` with a single `user`
        - messages belonging to this type of `conversation` MUST not save messages in the `message_records` table
- **conversation_key_uid** : the calculated key used to uniquely identify a `conversation`

#### Conversation Key Hash Calculation

Each `conversation` contains a hash which is used as an identifier in the application for unique identification. It is calculated by:

```
conversaton_key = sha256sum(
    domain_separator +
    conversation_type +
    conversation_member_count +
    conversation_member_public_keys...
```

The parameters are defined as:

- `domain_separator` : the ASCII-encoded string `ricochet-refresh-conversation`
- `conversation_type` : the type of the conversation as an 8-byte big-endian signed integer
- `conversation_member_count` : the number of users in this conversation as an 8-byte big-endian signed integer
- `conversation_member_public_keys...` : a sorted array of 32-byte identity `ed25519_public_keys`



### `conversation_members`

A table of all users in a conversation.

#### Schema
| Name | Type | Constraints |
| ---- | ---- | ----------- |
| conversation_rowid | INTEGER | NOT NULL REFERENCES conversations(rowid) |
| user_rowid | INTEGER | NOT NULL REFERENCES users(rowid) |
| | | UNIQUE(conversation_rowid, user_rowid) |

#### Members
- **conversation_rowid** : the rowid of a particular conversation
- **user_rowid** : the rowid of a user who is part of the associated conversation

### `message_records`

A table of all message records.

#### Schema
| Name | Type | Constraints |
| ---- | ---- | ----------- |
| conversation_rowid | INTEGER | NOT NULL REFERENCES conversations(rowid) |
| user_rowid | INTEGER | NOT NULL REFERENCES users(rowid) |
| record_sequence | INTEGER | NOT NULL CHECK(record_sequence >= 0) |
| message_sequence | INTEGER | NOT NULL CHECK (message_sequence >= 0) |
| create_timestamp | INTEGER | NOT NULL |
| message_content_rowid | INTEGER | NOT NULL UNIQUE REFERENCES message_contents(rowid) |
| signature_rowid | INTEGER | NOT NULL UNIQUE REFERENCES ed25519_signatures(rowid) |
| | | UNIQUE (conversation_rowid, user_rowid, record_sequence) |

#### Members
- **conversation_rowid** : the `conversation` this `message_record` belongs to
- **user_rowid** : the `user` which sent this `message_record`
- **record_sequence** : the sequence number of record modifications by `user` in a `conversation`
    - this value starts at `0` and auto-increments by `1` for each `user`+ `conversation` pair.
- **message_sequence** : the sequence number for messages sent by `user` in a `conversation`
    - this value starts at `0` and auto-increments by `1` with each new `message_record` unless the `message_record` is meant to replace an existing one
    - this determines the order in which records should appear when reading a conversation
    - if a message is edited, then there will be multiple `message_record` rows with identical `message_sequence` values but with differing `record_sequence` values
- **create_timestamp** : the UTC timestamp of when this message was first sent
    - milliseconds since the UNIX epoch
    - MUST be greater than or equal to the `create_timestamp` of the previous `message_record` (i.e. the `message_record` with the previous `record_sequence` value)
- **message_content_rowid** : the `message_content` associated with this `message_record`
- **signature_rowid** : an `ed25519_signature` created from this `message_record`'s `salt` and `message_content`. See the [Signature Calculation](#signature-calculation) for method of calculation.

#### Signature Calculation

Each `message_record` contains an `ed25519_signature` to verify the integrity of its associated metadata and contents. The sender signs the following payload using their own identity `ed25519_private_key`:

```
signature = ed25519_sign(
    domain_separator +
    previous_signature +
    conversation_key +
    user_identity_ed25519_public_key +
    record_sequence +
    message_sequence +
    create_timestamp +
    message_content_hash,
    sender_ed25519_private_key)
```

The parameters are defined as:

- `domain_separator` : the ASCII-encoded string `"ricochet-refresh-message-record"`
- `previous_signature` : the 64-byte `ed25519_signature` of the previous `message_record` (i.e. the `message_record` with the previous `record_sequence` for this conversation and user pair; if no such `message_record` exists (i.e. this is the first message for a user in a conversation), then this is 64 `0x00` bytes
- `conversaton_key` : the 32-byte key of the `conversation` this `message_record` belongs to
- `user_identity_ed25519_public_key` : the 32-bit identity `ed25519_public_key` of the user that authored this `message_record`
- `record_sequence` : the 8-byte big-endian `record_sequence` value for this `message_record`
- `message_sequence` : the 8-byte big-endian `message_sequence` value for this `message_record`
- `create_timestamp` : the 8-byte big-endian `create_timestamp` value for this `message_record`
- `message_content_hash` : the 32-byte `message_content` hash; see [Message Content Hash Calculation](#message-content-hash-calculation) for method of calculation.
- `sender_ed25519_private_key` : the `message_record` sender's 64-byte identity `ed25519_private_key`

### `message_contents`

A table of polymorphic message contents, along with a salt used for hashing.

#### Schema
| Name | Type | Constraints |
| ---- | ---- | ----------- |
| salt_rowid | INTEGER | NOT NULL UNIQUE REFERENCES salts(rowid) |
| message_type | INTEGER | NOT NULL CHECK(message_type >= 0 AND message_type <= 2) |
| tombstone_message_rowid | INTEGER | UNIQUE REFERENCES tombstone_messages(rowid) |
| text_message_rowid | INTEGER | UNIQUE REFERENCES text_messages(rowid) |
| file_share_message_rowid | INTEGER | UNIQUE REFERENCES file_share_messages(rowid) |
| | | CHECK((message_type = 0) = (tombstone_message_rowid IS NOT NULL)) |
| | | CHECK((message_type = 1) = (text_message_rowid IS NOT NULL)) |
| | | CHECK((message_type = 2) = (file_share_message_rowid IS NOT NULL)) |

#### Members
- **salt_rowid** : the `salt` used when calculating the hash of this `message_content`
- **message_type** : an enum identifying this message's type; MUST be one of:
    - Tombstoned(0) : a message which has been tombstoned (i.e. deleted or overridden by newer message)
    - Text(1) : a plain-text message
    - FileShare(2) : a file-share message
- **tombstone_message_rowid** : the `tombstone_message` content associated with this `message_content`; MUST NOT be NULL if `message_type` is `0`
- **text_message_rowid** : the `text_message` content associated with this `message_content`; MUST NOT be NULL  if `message_type` is `1`
- **file_share_message_rowid** : the `file_share_message` content associated with this `message_content`; MUST NOT be NULL if `message_type` is `2`

#### Message Content Hash Calculation

Each message type has a different method of hashing their content.

##### Tombstoned Message

```
message_content_hash = sha256sum(
    domain_separator +
    message_content_salt +
    original_message_content_hash +
    original_message_record_signature)
```

The parameters are defined as:
- `domain_separator` : the ASCII-encoded string `ricochet-refresh-tombstone-message`
- `message_content_salt` : the 32-byte `salt` associated with this `message_content`
- `original_message_content_hash` : the 32-byte `sha256_hash` of the `message_record`'s previous `message_content` prior to modification
- `original_message_record_signature` : the 64-byte `ed25519_signature` of the `message_record` prior to modification

##### Text Message

```
message_content_hash = sha256sum(
    domain_separator +
    message_content_salt +
    text)
```

The parameters are defined as:
- `domain_separator` : the ASCII-encoded string `ricochet-refresh-text-message`
- `message_content_salt` : the 32-byte `salt` associated with this `message_content`
- `text` : the variable-length utf8-encoded `text` string associated with this `message_content`

##### File Share Message

```
message_content_hash = sha256sum(
    domain_separator +
    message_content_salt +
    file_data_hash)
```

The parameters are defined as:
- `domain_separator` : the ASCII-encoded string `ricochet-refresh-file-share-message`
- `message_content_salt` : the 32-byte `salt` associated with this `message_content`
- `file_data_hash` : the 32-byte `sha256_hash` of the shared file's metadata and contents; see [File Data Hash Calculation](#file-data-hash-calculation) for method of calculation

### `tombstone_messages`

A table of otmbstoned messages. This table contains the message-content hash and signature of the message prior to being tombstoned to ensure the hash-chain can be verified after syncs, and to ensure original message contents are removed locally.

#### Schema
| Name | Type | Constraints |
| ---- | ---- | ----------- |
| original_message_content_hash_rowid | INTEGER | NOT NULL REFERENCES sha256_hashes(rowid) |
| original_message_record_signature_rowid | INTEGER | NOT NULL REFERENCES ed25519_signatures(rowid) |

#### Members
- **original_message_content_hash_rowid** : the hash of the associated `message_record`'s content prior to modification
- **original_message_record_signature_rowid** : the `ed25519_signature` of this `message_record`'s content prior to modification

### `text_messages`

A table of text messages.

#### Schema
| Name | Type | Constraints |
| ---- | ---- | ----------- |
| text | TEXT | NOT NULL |

#### Members
- **text** : the message's content

### `file_share_messages`

A table of file share messages.

#### Schema
| Name | Type | Constraints |
| ---- | ---- | ----------- |
| file_data_salt_rowid | INTEGER | NOT NULL REFERENCES salts(rowid) |
| file_size | INTEGER  | NOT NULL CHECK(file_size >= 0) |
| file_data_hash_rowid | INTEGER | NOT NULL REFERENCES sha256_hashes(rowid) |
| file_path | TEXT | |

#### Members
- **file_data_salt_rowid** : the `salt` used to calculate this `file_share_message`'s `file_data_hash`
- **file_size** : the size of the shared file in bytes
    - MUST NOT be a negative value
- **file_data_hash_rowid** : the `sha256_hash` of the file's metadata and contents;  see [File Data Hash Calculation](#file-data-hash-calculation) for method of calculation
- **file_path** : the OPTIONAL path to the file being shared on the local file-system
    - MUST NOT be NULL for the sender of a `file_share_message`
    - MUST be NULL for the receiver of a `file_share_message`

#### File Data Hash Calculation

Each `file_share_message` contains a hash of the shared file's metadata and contents. It is calculated by:

```
file_data_hash = sha256sum(
    domain_separator +
    file_data_salt +
    file_size +
    file_contents)
```

The parameters are defined as:

- `domain_separator` : the ASCII-encoded string `ricochet-refresh-file-data`
- `file_data_salt` : the 32-byte salt associated with this `file_share_message`
- `file_size` : the size of the shared file as an 8-byte big-endian signed integer
- `file_contents` : the shared file's contents as a length `file_size` buffer of bytes

### `salts`

A table for salt blobs used for calculating hashes

#### Schema

| Name | Type | Constraints |
| ---- | ---- | ----------- |
| value | BLOB | NOT NULL UNIQUE CHECK(LENGTH(value) = 32) |

#### Members
- **value** : a 32-byte buffer of cryptographically random bytes

### `sha256_hashes`

A table of sha256 hashes.

#### Schema
| Name | Type | Constraints |
| ---- | ---- | ----------- |
| value | BLOB | NOT NULL UNIQUE CHECK(LENGTH(value) = 32) |

#### Members
- **value** : a 32-byte buffer storing a sha256 hash

### `ed25519_private_keys`

A table of ed25519 private keys used to host identity and endpoint onion services.

#### Schema
| Name | Type | Constraints |
| ---- | ---- | ----------- |
| value | BLOB | NOT NULL UNIQUE CHECK(LENGTH(value) = 64) |

#### Members
- **value** : a 64-byte buffer storing an expanded ed25519 secret key

### `ed25519_public_keys`

A table of ed25519 public keys.

#### Schema
| Name | Type | Constraints |
| ---- | ---- | ----------- |
| value | BLOB | NOT NULL UNIQUE CHECK(LENGTH(value) = 32) |

#### Members
- **value** : a 32-byte buffer storing an ed25519 public key

### `ed25519_signatures`

A table of ed25519 cryptographic signatures used to verify the authenticity of `message_record` rows.

#### Schema
| Name | Type | Constraints |
| ---- | ---- | ----------- |
| value | BLOB | NOT NULL UNIQUE CHECK(LENGTH(value) = 64) |

#### Members
- **value** : a 64-byte buffer storing an ed25519 signature

### `x25519_private_keys`

A table of x25519 private keys used to decrypt endpoint onion service descriptors.

#### Schema
| Name | Type | Constraints |
| ---- | ---- | ----------- |
| value | BLOB | NOT NULL UNIQUE CHECK(LENGTH(value) = 32) |

#### Members
- **value** : a 32-byte buffer storing an x25519 secret key

### `x25519_public_keys`

A table of x25519 public keys used to encrypt endpoint onion service descriptors.

#### Schema
| Name | Type | Constraints |
| ---- | ---- | ----------- |
| value | BLOB | NOT NULL UNIQUE CHECK(LENGTH(value) = 32) |

#### Members
- **value** : a 32-byte buffer storing an x25519 public key

---

[^1]: RFC 2119 [https://www.rfc-editor.org/rfc/rfc2119](https://www.rfc-editor.org/rfc/rfc2119)

[^2]: Semantic Versioning [https://semver.org/](https://semver.org/)
