fs = require 'fs'
path = require 'path'
rules = require './rules'
log = require './logger'

# Compatibility settings - commented out for now
protocols = ['ip', 'tcp', 'udp']

# Standard snort rule format: action proto src_ip src_port direction dst_ip dst_port (options)
# Example: alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"SHELLCODE x86 setgid 0"; content:"|B0 B5 CD 80|"; reference:arachnids,284; classtype:system-call-detect; sid:649; rev:8;)
# Load a file, strip out useless rules, 
exports.parse = (name, raw) ->
  out = {rules: []}
  lines = raw.split '\n'
  #log.debug lines
  for line in lines
    splits = isValid line   
    if !splits
      continue
      
    fopts = []
    # This is extremely ugly but I really wanted to create a crazy one liner at one point in my life
    # This will join all of the options, remove invalid chars, split them up, split them up again then parse the name and value into json
    # and add it to our options object array for the line
    opts = splits[7...splits.length].join('').replace(/"/g, '').replace('(', '').replace(')', '').split ';'
    for val in opts
      if val.length <= 0 or !val
        continue
      temp = val.trim().split ':'
      obj = {}
      obj[temp[0]] = temp[1]
      fopts.push obj
    
    out.rules.push {action: splits[0], protocol: splits[1], src_ip: splits[2], src_port: splits[3], dst_ip: splits[5], dst_port: splits[6], options: fopts}
    # log.debug fopts
  fs.writeFileSync rules.location + name + '.srs', JSON.stringify(out)
  log.debug name + ' parser statistics: '
  log.debug out.rules.length + ' rules left after ' + (lines.length - out.rules.length) + ' invalid rules were removed'
    
# Remove any rules that arent usable
isValid = (contents) ->
  splits = contents.split ' '
  
  if contents is ''
    return false
      
  if contents.length < 1
    return false
  else if contents.indexOf('#') >= 0
    return false
  # else if splits[4] isnt '->'
  #  return false
  # else if splits[1] in protocols
  #  return true
  else
    return splits
