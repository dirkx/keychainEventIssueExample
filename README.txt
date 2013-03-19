
 Quick example to debug a key chain issue.

 https://developer.apple.com/library/mac/#documentation/security/Reference/keychainservices/Reference/reference.html

 Assumptions

 - Upon adding/removing a keychain in the keychain.app
   one expect a single kSecKeychainListChangedEvent event
   for each add/remove which contains at the very least
   a filled out keychain pointer in the SecKeychainCallbackInfo*
   passed.

 - Upon inserting/removing a chipcard, Kerberos stash or similar
   keychain bridged security realm - one would expect the same.

 Observations

 - On adding/removing a keychain file one gets indeed a single
   keychain event -- but with a 0x0 pointer in keychain.

 - On adding/removing a chipcard, token, kerberos KAC one gets
   some 12 tot 150 kSecKeychainListChangedEvent in quick succession
   each with a 0x0 pointer for both the keychain and item in the
   SecKeychainCallbackInfo struct passed in the callback.

 Tried on 10.8.3

