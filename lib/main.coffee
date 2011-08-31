require 'protege'
  
module.exports = 
  logger: require './logger'
  rules: require './rules'
  listener: require './engine/listener'
  package: require('./package').load()
