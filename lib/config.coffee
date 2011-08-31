path = require 'path'
module.exports =
  ruledir: path.join __dirname, 'rules/'
  snortcvs: 'http://rules.emergingthreats.net/open-nogpl/snort-edge/rules/emerging-'
  snortext: '.rules'
  ruleext: '.vrf'
