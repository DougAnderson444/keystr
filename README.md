# keystr

A proof on concept for combining provenance logs with passkeys to create a secure, multi-device, multi-key authentication system.

## Process Flow Example

- On mobile, user navigates to static website A that supports keystr authentication.
- New user, so the new plog, vlad, and passkey is created.
- passkey is added to the plog key entry set, and is now valid for the vlad & plog.
- User is authenticated to the vlad.
- User navigates to website B on desktop.
- Website B requests authentication via keystr.
- User selects vlad from list of available vlad's.
- User is prompted to authenticate using passkey.
- User authenticates using passkey.
- Since the desktop passkey is not listed in the plog key entry set, the user is prompted to add the desktop passkey to the plog.
- User scans the QR Code containing the passkey addition request.
- User approves the addition of the desktop passkey to the plog.
- User is now authenticated to website B on desktop.
- User now has a unified identity across multiple devices and websites.

## Risk & Threat model 

- If a device is lost or compromised, the user can remove the associated passkey from the plog, revoking access from that device.
- The plog serves as a single source of truth for valid authentication methods, allowing users to manage their access securely.
- The use of passkeys ensures that even if the plog is compromised, the attacker cannot authenticate without the corresponding passkey.
