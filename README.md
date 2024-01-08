# volatility3-plugins
A collection of volatility3 plugins I've made

- `windows.bitwardendump.BitwardenDump` - dumps plaintext credentials from an unlocked Bitwarden vault running as a browser extension. *(it's also possible to dump the whole unencrypted vault JSON together with the master key, but I've resorted to only dumping URLs, usernames and passwords in case some memory is inaccessible or corrupted)*
