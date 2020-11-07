#!/usr/bin/env python3
'''
@author: Winter Snowfall
@version: 1.20
@date: 23/10/2020
'''

import paramiko
import requests
import signal
import json
import logging
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
logger_file_handler = logging.FileHandler(log_file_full_path, mode='w', encoding='utf-8')
logger_format = '%(asctime)s %(levelname)s >>> %(message)s'
logger_file_handler.setFormatter(logging.Formatter(logger_format))
logging.basicConfig(format=logger_format, level=logging.INFO) #DEBUG, INFO, WARNING, ERROR, CRITICAL
logger = logging.getLogger(__name__)
logger.addHandler(logger_file_handler)

def sigterm_handler(signum, frame):
    logger.info('Stopping boincmon due to SIGTERM...')
    raise SystemExit(0)

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

if password == '':
    logger.critical('No password has been provided - exiting.')
    raise SystemExit(1)

logger.info('Service is starting...')

try:
    #reading from config file
    configParser.read(conf_file_full_path)
    
    BLINK_INTERVAL_NO_BOINC = configParser['GENERAL']['blink_interval_no_boinc']
    BLINK_INTERVAL_NO_WORK = configParser['GENERAL']['blink_interval_no_work']
    BLINK_INTERVAL_LESS_WORK = configParser['GENERAL']['blink_interval_less_work']
    LED_SERVER_ENDPOINT = configParser['GENERAL']['led_server_endpoint']
    LED_SERVER_TIMEOUT = int(configParser['GENERAL']['led_server_timeout'])
    LED_PAYLOAD_LEFT_PADDING = configParser['GENERAL']['led_payload_left_padding']
    LED_PAYLOAD_LEFT_PADDING_LEN = len(LED_PAYLOAD_LEFT_PADDING)
    LED_PAYLOAD_RIGHT_PADDING = configParser['GENERAL']['led_payload_right_padding']
    LED_PAYLOAD = configParser['GENERAL']['led_payload_format']
    BOINC_CPU_USAGE_THRESHOLD = int(configParser['GENERAL']['boinc_cpu_usage_threshold'])
    SCAN_INTERVAL = int(configParser['GENERAL']['scan_interval'])
    SSH_TIMEOUT = int(configParser['GENERAL']['ssh_timeout'])
    HEADERS = {'content-type': 'application/json'}
except:
    logger.critical('Could not parse configuration file. Please make sure the appropriate structure is in place!')
    raise SystemExit(2)

psw_helper = password_helper()
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
        current_host_cpus = int(configParser[f'HOST{current_host_no}']['cpus'])
        boinc_hosts_array.append(boinc_host(current_host_name, current_host_ip, current_host_username, current_host_password, 
                                            current_host_led_no, current_host_boinc_user, current_host_cpus))
        current_host_no += 1
        
except KeyError:
    logger.info(f'BOINC host info parsing complete. Read {current_host_no - 1} entries.')
    
#catch SIGTERM and exit gracefully
signal.signal(signal.SIGTERM, sigterm_handler)
    
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
            
            #add an element separator before each item
            if len(command_string) > LED_PAYLOAD_LEFT_PADDING_LEN:
                command_string += ', '
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                   
            try:
                ssh.connect(boinc_host_entry.ip, username=boinc_host_entry.username, password=boinc_host_entry.password, timeout=SSH_TIMEOUT)
                parent_ssh_command = f'ps -u {boinc_host_entry.boinc_username} -U {boinc_host_entry.boinc_username} | grep -w boinc | wc -l'
                logger.debug(f'Issuing parent ssh command: {parent_ssh_command}')
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(parent_ssh_command)
                
                ssh_stdin.close()
                output = int(ssh_stdout.read().decode('utf-8').strip())
                logger.debug(f'Parent ssh command output is: {output}')
                
                if output == 1:
                    logger.info('The BOINC service is running.')

                    ssh_command = (f'ps -h --ppid `ps -u {boinc_host_entry.boinc_username} -U {boinc_host_entry.boinc_username}' 
                                    ' | grep -w boinc | awk \'{print $1}\'` | wc -l')
                    logger.debug(f'Issuing ssh command: {ssh_command}')
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(ssh_command)
                    ssh_stdin.close()
                    output = int(ssh_stdout.read().decode('utf-8').strip())
                    logger.debug(f'ssh command output is: {output}')
                    
                    if output > 0:
                        if output < boinc_host_entry.host_cpus:
                            #if there is only one task running on the host
                            if output == 1:
                                usage_ssh_command = (f'ps -h -o pcpu --ppid `ps -u {boinc_host_entry.boinc_username} -U {boinc_host_entry.boinc_username}' 
                                                     ' | grep -w boinc | awk \'{print $1}\'` | awk \'{print $1}\'')
                                logger.debug(f'Issuing usage ssh command: {usage_ssh_command}')
                                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(usage_ssh_command)
                                ssh_stdin.close()
                                #using float, as the initial number may not be parsed by int
                                output = int(float(ssh_stdout.read().decode('utf-8').strip()))
                                logger.debug(f'Usage ssh command output is: {output}')
                                
                                #if the cpu usage of the task is more than BOINC_CPU_USAGE_THRESHOLD% of the host expected cpus 
                                if output > BOINC_CPU_USAGE_THRESHOLD * boinc_host_entry.host_cpus:
                                    logger.info('BOINC tasks are being worked on (expected cpu usage).')
                                    command_string += LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', '0')
                                else:
                                    logger.info('BOINC tasks are being worked on (below expected cpu usage).')
                                    command_string += LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', BLINK_INTERVAL_LESS_WORK)
                            
                            else:
                                logger.warning('BOINC tasks are being worked on (below expected task count).')
                                command_string += LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', BLINK_INTERVAL_LESS_WORK)
                            
                        else:
                            if output == boinc_host_entry.host_cpus:
                                logger.info('BOINC tasks are being worked on (expected task count).')
                                command_string += LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', '0')
                            else:
                                logger.warning('BOINC tasks are being worked on (more than expected task count).')
                                command_string += LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', '0')
                    
                    else:
                        logger.info('No BOINC tasks are being worked on.')
                        command_string += LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', BLINK_INTERVAL_NO_WORK)
                    
                else:
                    logger.info('The BOINC service is not running.')
                    command_string += LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', BLINK_INTERVAL_NO_BOINC)
                    
            except paramiko.ssh_exception.NoValidConnectionsError:
                logger.warning('The server could not be reached.')
                command_string += LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '0').replace('$led_blink', '0')
            
            except Exception:
                logger.error(f'Error occured during checkup - server may be down or experiencing issues.')
                #uncomment for debugging purposes only
                #raise
                command_string += LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '0').replace('$led_blink', '0')
            
            finally:
                ssh.close()
        
        #ending the command string
        command_string += LED_PAYLOAD_RIGHT_PADDING
                
        logger.info('Checkup rounds complete. Updating LEDs...')
        logger.debug(f'Sending payload: {command_string}')
        data = json.loads(command_string)
        requests.post(LED_SERVER_ENDPOINT, json=data, headers=HEADERS, timeout=LED_SERVER_TIMEOUT)
        logger.info('LEDs updated.')
                
        #regular sleep interval between checkups
        logger.info('Sleeping until next checkup...')
        sleep(SCAN_INTERVAL)
        
except KeyboardInterrupt:
    pass
    
logger.info('Exiting boincmon service...')
