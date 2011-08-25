#!/usr/bin/env node

/**
 * Module dependencies.
 */
require('coffee-script'); //This shouldn't make a difference but we may want to load .coffee files later?
var snortjs = require('snortjs');
var log = snortjs.logger;
var arguments = process.argv.splice(2);
var arg = arguments[0];
var items = arguments.splice(1);

switch (arg) {
case 'install':
  snortjs.rules.install(items);
  break;

case 'update':
  snortjs.rules.update()
  break;

case 'remove':
  snortjs.rules.remove(items);
  break;

case 'wipe':
  snortjs.rules.wipe();
  break;

case 'clean':
  snortjs.rules.clean();
  break;
  
case 'listen':
  snortjs.listener.listen(items);
  break;
  
case 'version':
  snortjs.info(snortjs.package.version);
  break;

default:
  log.info('Please enter a valid command. Reference');
  log.info('version -- Outputs version');
  log.info('install <items> -- Installs and parses rulesets from CVS');
  log.info('remove <items> -- Removes specified rulesets');
  log.info('update -- Reinstalls all rulesets from CVS');
  log.info('wipe -- Removes all rulesets');
  log.info('clean -- Deletes unused files');
  log.info('listen <options> -- Runs listener with options');
};
