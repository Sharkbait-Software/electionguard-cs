using System;

namespace ElectionGuard.Core;

public class KeyCeremony
{
    public void DoWork()
    {
        // All guardians generate their keys and submits the public keys/proofs
        // Each guardian uses the publickeys from other guardians to encrypt shares and submits them
        // Each guardian receives the encrypted shares meant for them and decrypts them.

        // Admin sends each guardian a guardian record
        // Each guardian verifies the guardian record matches the data they received in their shares.
        // Admin waits for guardians to ack
        // Admin finalizes the guardian record
        // Guardians verify that the election public keys in the finalized record match the preliminary guardian record
    }
}
