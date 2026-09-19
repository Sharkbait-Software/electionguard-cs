---
name: performance-testing
description: Information on how to performance test ElectionGuard. Any significant change made to ElectionGuard should at least verify the performance tests and note if there is any significant impact on performance since the last run.
---

# Overview

Performance in ElectionGuard is critical for several paths. The time it takes to encrypt a ballot can directly impact the voter's experience, especially when run on lower end hardware that is commonly seen in voting devices. Additionally, the time that it takes to perform the tally and decryption is impactful because it will often be done over tens of thousands to hundreds of thousands of ballots at a time.

To get more information on how to run performance tests, see the [performance testing README](perf/README.md).
