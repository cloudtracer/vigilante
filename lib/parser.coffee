fs = require 'fs'
path = require 'path'
rules = require './rules'
log = require './logger'
vars = require './engine/variables'

# Compatibility settings
protocols = ['ip', 'tcp']
ignored_options = ['rev', 'reference', 'sid', 'flow', 'fast_pattern', 'classtype']

# Standard snort rule format: action proto src_ip src_port direction dst_ip dst_port (options)
# Example: alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"SHELLCODE x86 setgid 0"; content:"|B0 B5 CD 80|"; reference:arachnids,284; classtype:system-call-detect; sid:649; rev:8;)
# Load a file, strip out useless rules, 
exports.parse = (name, raw) ->
  out = {rules: []}
  
  raw = stripComments raw
  lines = raw.split '\n'
      
  for line in lines
      
    splits = isValid line   
    if !splits
      continue
        
    opts = splits[7...splits.length].join('') # 7-end is our options
    splits = splits[0..6]; # Fuck the options, we dont need them anymore!
    fopts = parseOptions opts # Run options through parser
    
    # Go through each value in our rule and see if it is an engine expression
    # If so, replace it with the proper value
    ###
    for val in splits
      if vars.hasOwnProperty val
        splits[splits.indexOf(val)] = vars[val]
    ###
          
    # Commented out for now, we don't give a shit about the action because this isnt an IPS so its only going to alert anyways bruh
    # TODO: Write a system that takes 'action' into consideration and uses iptables to blacklist if the action is drop or whatever
    # out.rules.push {action: splits[0], protocol: splits[1], src_ip: splits[2], src_port: splits[3], dst_ip: splits[5], dst_port: splits[6], options: fopts}
      
    out.rules.push {protocol: splits[1], src_ip: splits[2], src_port: splits[3], dst_ip: splits[5], dst_port: splits[6], options: fopts}
    # log.debug fopts
  fs.writeFileSync path.normalize(rules.location + name + '.prf'), JSON.stringify(out, null, 2)
  log.debug name + ' was parsed and installed!'
  log.debug out.rules.length + ' rules left after ' + (lines.length - out.rules.length) + ' invalid rules were removed'
  log.debug 'file was written to ' + path.normalize(rules.location + name + '.prf')
    
# Parses and filters options
parseOptions = (opts) ->
  fopts = []
  
  # filter parenthesis from start and end of options
  if opts.charAt(0) is '('
    opts = opts.substring(1, opts.length)
  
  if opts.charAt(opts.length-1) is ')'
    opts = opts.substring(0, opts.length-1)
  
  # get rid of any quotes, we dont need them bruv
  opts = opts.replace(/"/g, '').split ';'
  for val in opts
    if !val or val.length <= 1
      continue
              
    temp = val.trim().split ':'
    
    if temp[0] in ignored_options
      continue
    
    #If the object is just a single word argument, give it a shim value for the sake of standards
    if !temp[1]
      temp.push 'true'
    
    #If we lost the argument somewhere, fuck it    
    temp[1] ?= 'true'
    
    # If our options value is a term from engine variables, replace it with its proper value
    if vars.hasOwnProperty temp[1]
      temp[1] = vars[temp[1]]
      
    obj = {}
    obj[temp[0]] = temp[1]
    fopts.push obj
      
  return fopts
        
# Removes any lines containing a hash character, pretty simple
stripComments = (raw) ->
  lines = raw.split '\n'
  for line in lines
    if !line
      continue
    if line.indexOf('#') > -1 
      lines.splice lines.indexOf(line), 1
  return lines.join '\n'
    
# Remove any rules that arent usable
isValid = (line) ->
  splits = line.split ' '
  
  if !line
    return false
  else if line.length <= 1
    return false
  else if line.indexOf('#') > -1
    return false
  else if splits[4] isnt '->'
    return false
  else if !(splits[1] in protocols)
    return false
      
  else
    return splits
