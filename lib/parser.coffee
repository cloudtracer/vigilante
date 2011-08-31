fs = require 'fs'
path = require 'path'
rules = require './rules'
log = require './logger'
vars = require './engine/variables'
config = require './config'

# Compatibility settings
engine_terms = require './engine/variables'
ignored_terms = ['rev', 'reference', 'sid', 'flow', 'fast_pattern', 'classtype', 'metadata', 'gid']
search_terms = ['nocase', 'depth', 'distance', 'within', 'http_uri', 'http_raw_uri', 'http_header', 'http_raw_header', 'http_cookie', 'http_raw_cookie', 'http_method', 'http_client_body', 'http_stat_code', 'http_stat_msg', 'file_data']
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
    fixedOptions = condenseOptions condenseOptions formatOptions formatOptions formatOptions parseOptions rawOptions # Run options through parser, Run options through formatter so we get fancy PRF output
    
    out.rules.push {protocol: args[1], src_ip: args[2], src_port: args[3], dst_ip: args[5], dst_port: args[6], options: fixedOptions}
    
  fs.writeFileSync path.normalize(config.ruledir + name + config.ruleext), out.prettify()
  log.info name + ' was downloaded, parsed, and installed!'
  log.info out.rules.length + ' rules left after '+ (lines.length - out.rules.length) + ' invalid rules were removed'
  log.debug name + ' was written to ' + path.normalize(config.ruledir + name + config.ruleext)
 
# Makes the options smaller and easier to parse
condenseOptions = (opts) ->
  for opt in opts
    unless opt? 
      continue
    
    #look ahead    
    if opts[_i+1]? and opts[_i+1].getKey().equalsIgnoreCase opt.getKey()
      obj = {}
      if Object.isArray opt.getValue()
        obj[opt.getKey()] = opt.getValue().concat opts[_i+1].getValue()
      else
        obj[opt.getKey()] = [opt.getValue(), opts[_i+1].getValue()]
        
      opts.replaceIndex _i, obj  
      opts.removeIndex _i+1
    
    #look back    
    if opts[_i-1]? and opts[_i-1].getKey().equalsIgnoreCase opt.getKey()
      obj = {}
      if Object.isArray opts[_i-1].getValue()
        obj[opt.getKey()] = opts[_i-1].getValue().concat opt.getValue()
      else
        obj[opt.getKey()] = [opts[_i-1].getValue(), opt.getValue()]
        
      opts.replaceIndex _i-1, obj  
      opts.removeIndex _i
        
  return opts
    
# Formats options into PRF format
formatOptions = (opts) ->
  
  # replaces any shitty shit with better shitty shit
  for opt in opts
    unless opt? 
      continue
    
    if opt.getKey().startsWith 'content'
      for param in search_terms
          if opts[_i+1]? and opts[_i+1].getKey().equalsIgnoreCase param
            newName = opt.getKey() + '_' + param 
            
            if !Object.isEmpty opts[_i+1].getValue()
              newName += '-' + opts[_i+1].getValue()
              
            obj = {}
            obj[newName] = opt.getValue()
            opts.replaceIndex _i, obj   
            opts.removeIndex _i+1
           
  return opts
        
# Parses and filters options
parseOptions = (line) ->
  fline = []
  
  # filter parenthesis from start and end of options
  if line.startsWith '('
    line = line.substring 1, line.length
  
  if line.endsWith ')'
    line = line.substring 0, line.length-1
  
  # get rid of any quotes, we dont need them bruv
  line = line.replace(/"/g, '').split ';'
  for val in line
    if !val or val.length <= 1
      continue
              
    temp = val.trim().split ':'
    
    # temp[0] = name, temp[1] = value
    
    if temp[0] in ignored_terms
      continue
        
    # If we lost the arg somewhere or it never had one, FUCK IT    
    temp[1] ?= ''
    
    # run the option through replacements and see if it needs to go
    for rep in replacements
      if temp[0].equalsIgnoreCase rep[0]
        temp[0] = rep[1]
        
      if temp[1].equalsIgnoreCase rep[0]
        temp[1] = rep[1]
      
    obj = {}
    obj[decodeHTML(temp[0])] = decodeHTML(temp[1])
    fline.push obj
      
  return fline

# Turns snort HTML encoding into standard encoding then unescapes it
decodeHTML = (line) ->
  if Object.isString(line) and line.contains('|')
    matches = line.match /\|([0-9a-fA-F]{2})\|/gi
    if matches?
      for mat in matches
        line = line.replace(mat, '%' + mat.replace(/\|/gi, '').upcase())
  return unescape(line)
    
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
