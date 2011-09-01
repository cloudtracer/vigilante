**Vigilante is an open source intrusion detection system (IDS) written in NodeJS. Protege aims to be compatible with existing Snort and mod_security rules**


## Installation

Vigilante requires libpcap to be installed.

    $ sudo apt-get install libpcap-dev
    
To install Vigilante, use [npm](http://github.com/isaacs/npm):

    $ npm install -g vigilante --unsafe
    
Opening the capture interface on most operating systems requires root access, make sure to install/run Vigilante on a user with the right privs!

## Configuration

TODO

## Usage

TODO

## Examples

You can view examples in the [example folder.](https://github.com/Contra/vigilante/tree/master/examples)

## Vigilante Rule Format

### VRF is fully compatible with all Snort expressions, just use the parser to convert any Snort rules to VRF

Standard Snort rule format: ```action proto src_ip src_port direction dst_ip dst_port (options)```
Example: ```alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"SHELLCODE x86 setgid 0"; content:"|B0 B5 CD 80|"; reference:arachnids,284; classtype:system-call-detect; sid:649; rev:8;)```

Standard Vigilante rule format:
```
        message: 'attack details to display'
        protocol: proto
        source: 'ip range'
        source_port: port_numbers
        destination: 'ip range'
        destination_port: port_numbers
        parameters: any scan/search specifications
```
Example: 
```
        message: 'SHELLCODE x86 setgid 0'
        protocol: ip
        source: $EXTERNAL_NET
        source_port: $SHELLCODE_PORTS
        destination: $HOME_NET
        destination_port: any
        parameters:
             contains: '|B0 B5 CD 80|'
```
     
## Contributors

- [Contra](https://github.com/Contra)

## LICENSE

(MIT License)

Copyright (c) 2011 Contra <contra@australia.edu>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
