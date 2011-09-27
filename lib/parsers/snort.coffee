fs = require 'fs'
async = require 'async'
path = require 'path'
rules = require '../rules'
log = require 'node-log'
vars = require '../engine/variables'
config = require '../config'

# Compatibility settings
engine_terms = require '../engine/variables'
ignored_terms = ['rev', 'reference', 'sid', 'flow', 'fast_pattern', 'classtype', 'metadata', 'gid']
search_terms = ['nocase', 'depth', 'distance', 'within', 'http_uri', 'http_raw_uri', 'http_header', 'http_raw_header', 'http_cookie', 'http_raw_cookie', 'http_method', 'http_client_body', 'http_stat_code', 'http_stat_msg', 'file_data']
replacements = [['pcre', 'pattern'], ['msg', 'message']]
 
# Makes the options smaller and easier to parse
condenseOptions = (opts) ->
  for opt in opts
    unless opt? 
      continue
    for sopt in opts
      unless sopt? 
        continue

      if sopt isnt opt and sopt.getKey() is opt.getKey()
        obj = {}
        if !Object.isArray opt.getValue()
          opt[opt.getKey()] = [opt.getValue()]
        obj[opt.getKey()] = opt.getValue().concat sopt.getValue()
        opts.replaceIndex _i, obj  
        opts.removeIndex _j 
  return opts
    
# Formats options into PRF format
formatOptions = (opts) ->
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
  if line.startsWith '(' then line = line.substring 1, line.length
  if line.endsWith ')' then line = line.substring 0, line.length-1
  line = line.replace(/"/g, '').split ';'
  for val in line
    if !val or val.length <= 1
      continue
              
    temp = val.trim().split ':'
    if temp[0] in ignored_terms
      continue
          
    temp[1] ?= ''
    
    # run the option through replacements and see if it needs to go
    for rep in replacements
      if temp[0].equalsIgnoreCase rep[0] then temp[0] = rep[1] 
      if temp[1].equalsIgnoreCase rep[0] then temp[1] = rep[1]
      
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
        
# Load a file, strip out useless rules, 
module.exports =
  parse: (name, raw, cb) ->
    rules = []
    parseIt = (line, call) ->
      if !isValid line then return call()
      args = line.split ' '
      rawOptions = args[7...args.length].join('') # 7-to-end is our options
      fixedOptions = condenseOptions condenseOptions formatOptions formatOptions formatOptions parseOptions rawOptions
      rules.push {protocol: args[1], src_ip: args[2], src_port: args[3], dst_ip: args[5], dst_port: args[6], options: fixedOptions} 
      return call()
        
    lines = raw.split '\n'   
    async.forEach lines, parseIt, -> 
      log.info rules.length + ' rules left after '+ (lines.length - rules.length) + ' invalid rules were removed'
      return cb rules
