fs = require 'fs'
path = require 'path'
rules = require './rules'
log = require './logger'
vars = require './engine/variables'

# Compatibility settings
protocols = ['ip', 'tcp']
ignored_options = ['rev', 'reference', 'sid', 'flow', 'fast_pattern', 'classtype', 'metadata', 'gid']

# Standard snort rule format: action proto src_ip src_port direction dst_ip dst_port (options)
# Example: alert ip $EXTERNAL_NET $SHELLCODE_PORTS -> $HOME_NET any (msg:"SHELLCODE x86 setgid 0"; content:"|B0 B5 CD 80|"; reference:arachnids,284; classtype:system-call-detect; sid:649; rev:8;)
# Load a file, strip out useless rules, 
exports.parse = (name, raw) ->
  out = {rules: []}
  
  lines = raw.split '\n'
      
  for line in lines
      
    splits = isValid line   
    if !splits
      continue
        
    opts = splits[7...splits.length].join('') # 7-end is our options
    splits = splits[0..6]; # Fuck the options, we dont need them anymore!
    
    fopts = parseOptions opts # Run options through parser
    fopts = formatOptions fopts # Run options through formatter so we get fancy PRF output
    
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
 
# Formats options into PRF format
formatOptions = (opts) ->
  contentParams = ['nocase', 'http_uri', 'http_raw_uri', 'http_header', 'http_raw_header', 'http_cookie', 'http_raw_cookie', 'http_method', 'http_client_body', 'http_stat_code', 'http_stat_msg', 'file_data']
  
  toreplace = ['pcre', 'msg']
  replacements = ['pattern', 'message']
  
  # replaces any shitty shit with better shitty shit
  for opt in opts
    if !opt
      continue
    
    # condense all content arguments into one object
    for val of opt
      # replace any shitty keys with new shitty keys
      if toreplace.indexOf(val) > -1
        idx = toreplace.indexOf(val)
        obj = {}
        obj[replacements[idx]] = opt[val]
        opts.splice _i, 1, obj
          
      # condense all content arguments into one object
      if val.indexOf('content') is 0
        for param in contentParams
          if opts[_i+1]? and opts[_i+1].hasOwnProperty param
            opts.splice _i+1, 1 # remove the param
            newName = val + '_' + param
            obj = {}
            obj[newName] = opt[val]
            opts.splice _i, 1, obj # replace content    
          
  return opts
        
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
    
    #If we lost the argument somewhere, fuck it    
    temp[1] ?= 'true'
    
    # If our options value is a term from engine variables, replace it with its proper value
    # if vars.hasOwnProperty temp[1]
    #  temp[1] = vars[temp[1]]
      
    obj = {}
    obj[temp[0]] = temp[1]
    fopts.push obj
      
  return fopts
    
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
