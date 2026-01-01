# keystr

> Key Stuff Through Relays

A proof on concept experiment for combining provenance logs with passkeys to create a secure, multi-device, mulit-client, multi-key authentication system.

## Why: Nostr use case 

- log into a Nostr client from two different devices
- want to avoid copying and pasting private keys
- want to be able to delegate posting to a social media manager app without sharing private keys
- want to be able to revoke access from a lost or compromised device
- want to have a unified identity across multiple Nostr clients
- want to be able to have multiple keys and key types (secp256k1, ed25519, P256, etc) associated with the same identity

This currently cannot be done with a npub identifier alone. A better solution is needed.

## MVP: Same website, multiple devices

- User creates a vlad (verifiable log of authentic devices) on device A when first visiting a website.
- User creates a plog (provenance log) that contains key entries for each device's passkey.
- When the user visits the same website on device B, they can authenticate using the vlad and plog from device A.
- If device B's passkey is not in

## Process Flow Example

- On device A, user navigates to the website supporting keystr authentication.
- The user is new, so the new plog, vlad, and passkey is created.
- passkey public key is added to the plog key entry set, and is now valid for the vlad & plog.
- User is authenticated to the vlad.
- User navigates to the website on device B.
- Website requests authentication via keystr.
- User selects/enters vlad/plog available (passkey from device A sent to device B by the passkey backend).
- User is prompted to authenticate using passkey.
- User authenticates using passkey.

## Crosss-site authentication with unified identity

- If the users wants to use this same identifier on another website (classic example, another Nostr client but for the same account), say, website B, the passkey is not listed in the plog key entry set for the vlad, the user is prompted to add the website B passkey to the plog by adding it while auth'd on website A.
- User scans the QR Code containing the passkey addition request.
- User approves the addition of the website B passkey to the plog.
- User is now authenticated to website B authorized to publish under the vlad.
- User now has a unified identity across multiple devices and websites.

## Risk & Threat model 

- If a device is lost or compromised, the user can remove the associated passkey from the plog, revoking access from that device.
- The plog serves as a single source of truth for valid authentication methods, allowing users to manage their access securely.
- The use of passkeys ensures that even if the plog is compromised, the attacker cannot authenticate without the corresponding passkey.
