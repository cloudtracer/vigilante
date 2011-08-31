fs = require 'fs'
path = require 'path'
rules = require './rules'
log = require './logger'
vars = require './engine/variables'
config = require './config'

# Compatibility settings
engine_terms = require './engine/variables'
ignored_terms = ['rev', 'reference', 'sid', 'flow', 'fast_pattern', 'classtype', 'metadata', 'gid']
search_terms = ['nocase', 'http_uri', 'http_raw_uri', 'http_header', 'http_raw_header', 'http_cookie', 'http_raw_cookie', 'http_method', 'http_client_body', 'http_stat_code', 'http_stat_msg', 'file_data']
replacements = [['pcre', 'pattern'], ['msg', 'message']]
  
# Load a file, strip out useless rules, 
exports.parse = (name, raw) ->
  out = {rules: []}
  
  lines = raw.split '\n'
      
  for line in lines
    
    if !isValid line
      continue  
        
    args = line.split ' '
        
    rawOptions = args[7...args.length].join('') # 7-end is our options
    fixedOptions = formatOptions parseOptions rawOptions # Run options through parser, Run options through formatter so we get fancy PRF output
    
    out.rules.push {protocol: args[1], src_ip: args[2], src_port: args[3], dst_ip: args[5], dst_port: args[6], options: fixedOptions}
    
  fs.writeFileSync path.normalize(config.ruledir + name + config.ruleext), out.prettify()
  log.info name + ' was downloaded, parsed, and installed!'
  log.info out.rules.length + ' rules left after '+ (lines.length - out.rules.length) + ' invalid rules were removed'
  log.debug name + ' was written to ' + path.normalize(config.ruledir + name + config.ruleext)
 
# Formats options into PRF format
formatOptions = (opts) ->
  
  # replaces any shitty shit with better shitty shit
  for opt in opts
    if !opt?
      continue
    
    if opt.getKey().startsWith 'content'
      for param in search_terms
          if opts[_i+1]? and opts[_i+1].hasOwnProperty param
            opts.removeIndex _i+1
            newName = opt.getKey() + '_' + param
            obj = {}
            obj[newName] = opt.getValue()
            opts.replaceIndex _i, obj          
  return opts.unique true
        
# Parses and filters options
parseOptions = (opts) ->
  fopts = []
  
  # filter parenthesis from start and end of options
  if opts.startsWith '('
    opts = opts.substring 1, opts.length
  
  if opts.endsWith ')'
    opts = opts.substring 0, opts.length-1
  
  # get rid of any quotes, we dont need them bruv
  opts = opts.replace(/"/g, '').split ';'
  for val in opts
    if !val or val.length <= 1
      continue
              
    temp = val.trim().split ':'
    
    # temp[0] = name, temp[1] = value
    
    if temp[0] in ignored_terms
      continue
        
    # If we lost the arg somewhere or it never had one, FUCK IT    
    temp[1] ?= "WE'LL DO IT LIVE"
    
    # run the option through replacements and see if it needs to go
    for rep in replacements
      if temp[0].equalsIgnoreCase rep[0]
        temp[0] = rep[1]
        
      if temp[1].equalsIgnoreCase rep[0]
        temp[1] = rep[1]
      
    obj = {}
    obj[temp[0]] = temp[1]
    fopts.push obj
      
  return fopts
    
# Remove any rules that arent usable
isValid = (line) ->
  if !line?
    return false
  else if Object.isEmpty line
    return false
  else if line.contains '#'
    return false    
  else
    return true
