pcap = require 'pcap'
log = require './logger'

exports.listen = (options) ->
  log.debug 'Starting listener with options: '
  log.debug 'Protocol - ' + options[0]
    
  tcp = pcap.createSession '', options[0]
  log.info 'SnortJS listening on ' + tcp.device_name
  tcp.on 'packet', (raw_packet) ->
    packet = pcap.decode.packet raw_packet
    data = packet.link.ip.tcp.data
    if data
      log.debug pcap.print.packet packet
      log.debug data.toString()
