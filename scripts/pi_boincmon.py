#!/usr/bin/env python3
'''
@author: Winter Snowfall
@version: 1.00
@date: 23/02/2020
'''

import paramiko
import requests
import json
import logging
from sys import exit
from logging.handlers import RotatingFileHandler
from configparser import ConfigParser
from os import path
from time import sleep
from pi_password import password_helper

##global parameters init
configParser = ConfigParser()

##conf file block
conf_file_full_path = path.join('..', 'conf', 'boinc_host.conf')

##logging configuration block
log_file_full_path = path.join('..', 'logs', 'pi_boincmon_service.log')
logger_format = '%(asctime)s %(levelname)s >>> %(message)s'
logger_file_handler = RotatingFileHandler(log_file_full_path, maxBytes=0, backupCount=0, encoding='utf-8')
logger_file_formatter = logging.Formatter(logger_format)
logger_file_handler.setFormatter(logger_file_formatter)
logging.basicConfig(format=logger_format, level=logging.INFO) #DEBUG, INFO, WARNING, ERROR, CRITICAL
logger = logging.getLogger(__name__)
logger.addHandler(logger_file_handler)

#reading from config file
configParser.read(conf_file_full_path)

BLINK_INTERVAL_NO_BOINC = configParser['GENERAL']['blink_interval_no_boinc']
BLINK_INTERVAL_NO_WORK = configParser['GENERAL']['blink_interval_no_work']
BLINK_INTERVAL_LESS_WORK = configParser['GENERAL']['blink_interval_less_work']
LED_SERVER_ENDPOINT = configParser['GENERAL']['led_server_endpoint']
LED_SERVER_TIMEOUT = int(configParser['GENERAL']['led_server_timeout'])
LED_PAYLOAD_LEFT_PADDING = configParser['GENERAL']['led_payload_left_padding']
LED_PAYLOAD_RIGHT_PADDING = configParser['GENERAL']['led_payload_right_padding']
LED_PAYLOAD = configParser['GENERAL']['led_payload_format']
SCAN_INTERVAL = int(configParser['GENERAL']['scan_interval'])
SSH_TIMEOUT = int(configParser['GENERAL']['ssh_timeout'])
HEADERS = {'content-type': 'application/json'}

psw_helper = password_helper()

class boinc_host:
    def __init__(self, name, ip, username, password, led_no, boinc_username, host_cpus):
        self.name = name
        self.ip = ip
        self.username = username
        self.password = password
        self.led_no = led_no
        self.boinc_username = boinc_username
        self.host_cpus = host_cpus
        
#read the master password from the command line
password = input('Please enter the master password: ')

if password is None or password == '':
    logger.critical('No password has been provided - exiting.')
    exit(1)

logger.debug("<password>")
logger.info('Service is starting...')

boinc_hosts_array = []
current_host_no = 1

try:
    while True:
        #name of the remote BOINC host
        current_host_name = configParser[f'HOST{current_host_no}']['name']
        #ip address or hostname of the remote host
        current_host_ip = configParser[f'HOST{current_host_no}']['ip']
        #username used for the ssh connection
        current_host_username = configParser[f'HOST{current_host_no}']['username']
        #encrypted password of the above user - use the password utilities script to get the encrypted text
        current_host_password = psw_helper.decrypt_password(password, configParser[f'HOST{current_host_no}']['password'])
        #led number linked to the BOINC host
        current_host_led_no = configParser[f'HOST{current_host_no}']['led_no']
        #remote user under which the BOINC processes are being run
        current_host_boinc_user = configParser[f'HOST{current_host_no}']['boinc_user']
        #number of expected tasks on the remote host
        current_host_task_no = configParser[f'HOST{current_host_no}']['task_no']
        boinc_hosts_array.append(boinc_host(current_host_name, current_host_ip, current_host_username, current_host_password, 
                                            current_host_led_no, current_host_boinc_user, current_host_task_no))
        current_host_no += 1
        
except KeyError:
    logger.info(f'BOINC host info parsing complete. Read {current_host_no - 1} entries.')
    
try:
    while True:
        logger.info('Starting checkup rounds...')
        #turn on the update status routine
        on_status_routine = json.loads(LED_PAYLOAD_LEFT_PADDING + LED_PAYLOAD.replace('$led_no', '0').replace('$led_state', '1').replace('$led_blink', '0') + LED_PAYLOAD_RIGHT_PADDING)
        requests.post(LED_SERVER_ENDPOINT, json=on_status_routine, headers=HEADERS, timeout=LED_SERVER_TIMEOUT)
        
        #preparing the final command string
        command_string = LED_PAYLOAD_LEFT_PADDING
        
        for boinc_host_entry in boinc_hosts_array:
            logger.info(f'Checking {boinc_host_entry.name}...')
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                   
            try:
                ssh.connect(boinc_host_entry.ip, username=boinc_host_entry.username, password=boinc_host_entry.password, timeout=SSH_TIMEOUT)
                parent_ssh_command = f'ps -u {boinc_host_entry.boinc_username} -U {boinc_host_entry.boinc_username} | grep boinc | wc -l'
                logger.debug(f'Issuing parent ssh command: {parent_ssh_command}')
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(parent_ssh_command)
                
                ssh_stdin.close()
                output = ssh_stdout.read().decode('utf-8').strip()
                logger.debug(output)
                
                if int(output) == 1:
                    logger.info('The BOINC service is running.')

                    ssh_command = ''.join(("ps -h --ppid `ps -u ", boinc_host_entry.boinc_username, " -U ", 
                                            boinc_host_entry.boinc_username, " | grep boinc | awk '{print $1}'` | wc -l"))
                    logger.debug(f'Issuing ssh command: {ssh_command}')
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(ssh_command)
                    ssh_stdin.close()
                    output = ssh_stdout.read().strip().decode('utf-8')
                    logger.debug(output)
                    
                    if output is not None and int(output) > 0:
                        if int(output) < int(boinc_host_entry.host_cpus):
                            #if there is only one task running on the host
                            if int(output) == 1:
                                usage_ssh_command = ''.join(("ps -h -o pcpu --ppid `ps -u ", boinc_host_entry.boinc_username, " -U ", 
                                                    boinc_host_entry.boinc_username, " | grep boinc | awk '{print $1}'` | awk '{print $1}'"))
                                logger.debug(f'Issuing usage ssh command: {usage_ssh_command}')
                                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(usage_ssh_command)
                                ssh_stdin.close()
                                output = ssh_stdout.read().strip().decode('utf-8')
                                logger.debug(output)
                                
                                #if the cpu usage of the task is more than 75% of the host expected cpus 
                                #(using float, as the initial number may not be parsed by int)
                                if int(float(output)) > 75 * int(boinc_host_entry.host_cpus):
                                    logger.info('BOINC tasks are being worked on (expected cpu usage).')
                                    command_string += ''.join((', ', LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', '0')))
                                else:
                                    logger.info('BOINC tasks are being worked on (below expected cpu usage).')
                                    command_string += ''.join((', ', LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', BLINK_INTERVAL_LESS_WORK)))
                            
                            else:
                                logger.warning('BOINC tasks are being worked on (below expected task count).')
                                command_string += ''.join((', ', LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', BLINK_INTERVAL_LESS_WORK)))
                            
                        else:
                            if int(output) == int(boinc_host_entry.host_cpus):
                                logger.info('BOINC tasks are being worked on (expected task count).')
                                command_string += ''.join((', ', LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', '0')))
                            else:
                                logger.warning('BOINC tasks are being worked on (more than expected task count).')
                                command_string += ''.join((', ', LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', '0')))
                    
                    else:
                        logger.info('No BOINC tasks are being worked on.')
                        command_string += ''.join((', ', LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', BLINK_INTERVAL_NO_WORK)))
                    
                else:
                    logger.info('The BOINC service is not running.')
                    command_string += ''.join((', ', LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', BLINK_INTERVAL_NO_BOINC)))
                    
            except paramiko.ssh_exception.NoValidConnectionsError:
                logger.warning('The server could not be reached.')
                command_string += ''.join((', ', LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '0').replace('$led_blink', '0')))
            
            except Exception as error:
                logger.error(f'Error occured during checkup - server may be down or experiencing issues.')
                #uncomment for debugging only
                logger.error(repr(error))
                command_string += ''.join((', ', LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '0').replace('$led_blink', '0')))
            
            finally:
                ssh.close()
                
        logger.info('Checkup rounds complete. Updating LEDs...')
        #ending the command string
        command_string += LED_PAYLOAD_RIGHT_PADDING
        #compensate for the first element
        command_string = command_string.replace(LED_PAYLOAD_LEFT_PADDING + ', ', LED_PAYLOAD_LEFT_PADDING)
        logger.debug(f'Sending payload: {command_string}')
        data = json.loads(command_string)
        requests.post(LED_SERVER_ENDPOINT, json=data, headers=HEADERS, timeout=LED_SERVER_TIMEOUT)
        logger.info('LEDs updated.')
                
        #regular sleep interval between checkups
        logger.info('Sleeping until next checkup...')
        #sleep for 20 minutes
        sleep(SCAN_INTERVAL)
        
except Exception as error:
    logger.error(repr(error))
    logger.info('Exiting boincmon service...')
