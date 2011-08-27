require 'colors'
  
module.exports =
  log: (str) ->
    console.log str
  
  debug: (str) ->
    console.log '[' + 'Protege'.magenta, 'DEBUG'.white.inverse + ']', str	
      
  info: (str) ->
    console.log '[' + 'Protege'.magenta, 'info'.white + ']', str
      
  warn: (str) ->
    console.log '[' + 'Protege'.magenta, 'warn'.yellow + ']', str

  error: (str) ->
    console.log '[' + 'Protege'.magenta, 'ERROR'.red.inverse + ']', str
