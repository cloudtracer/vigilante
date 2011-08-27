local = '[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]'
any = '[0.0.0.0]'

module.exports =
  $HOME_NET: local
  $EXTERNAL_NET: any
  $HTTP_SERVERS: local
  $SMTP_SERVERS: local
  $SQL_SERVERS: local
  $DNS_SERVERS: local
  $TELNET_SERVERS: local
  $AIM_SERVERS: any
  # These vars are required if you're using the Digitalbond Scada signatures in the scada.rules category
  $DNP3_SERVER: local
  $DNP3_CLIENT: local
  $MODBUS_CLIENT: local
  $MODBUS_SERVER: local
  $ENIP_CLIENT: local
  $ENIP_SERVER: local
  $HTTP_PORTS: '80'
  $SHELLCODE_PORTS: '!80'
  $ORACLE_PORTS: '1521'
  $SSH_PORTS: '22'
  $DNP3_PORTS: '20000'
