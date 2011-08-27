# TODO

### Minor

* Write configuration/usage instructions in README
* Central server for pre-parsed rules
* Loading of local files to rule parser/loader
* Grouped rulesets. Example: Installing 'recommended' would install only the good shit

### Major

* Write mod_security parser that strips incompatible snort rules out and converts the rest to JSON
* Separate rules by transport type (TCP, UDP, ICMP, etc.) and run separate pcap listeners for each type
* Have one redis instance per transport type/pcap listener
* DESIGN EFFICIENT PACKET MANAGER
