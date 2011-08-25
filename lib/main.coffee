module.exports = 
  logger: require './logger'
  rules: require './rules'
  listener: require './listener'
  package: require('./package').load()
