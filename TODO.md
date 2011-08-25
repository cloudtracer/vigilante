# TODO

### Minor

* Backup server for snort rules
* Pre-parsed rulesets? Maybe. Would be a pain in the ass to update constantly
* Use a faster JSON parser (I saw some C one that claimed to be faster than the native one)

* Per-project rulesets. Right now snort rules are global per machine
* Grouped rulesets. Example: Installing 'recommended' would install only the good shit

### Major

* Write Snort parser that strips incompatible snort rules out and converts the rest to JSON
* Sort rules by transport type (TCP, UDP, ICMP, etc.) and run separate pcap listeners for each type
