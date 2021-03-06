#!/usr/bin/env python3
'''
@author: Winter Snowfall
@version: 1.40
@date: 17/01/2021
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
#uncomment for debugging purposes only
#import traceback

##global parameters init
configParser = ConfigParser()

##conf file block
conf_file_full_path = path.join('..', 'conf', 'boinc_host.conf')

##logging configuration block
log_file_full_path = path.join('..', 'logs', 'pi_boincmon.log')
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
    def __init__(self, name, simulated, ip, username, password, led_no, boinc_username, threads):
        self.name = name
        self.simulated = simulated
        self.ip = ip
        self.username = username
        self.password = password
        self.led_no = led_no
        self.boinc_username = boinc_username
        self.threads = threads

#read the master password from the command line
password = input('Please enter the master password: ')

if password == '':
    logger.critical('No password has been provided - exiting.')
    raise SystemExit(1)

logger.info('Service is starting...')

try:
    #reading from config file
    configParser.read(conf_file_full_path)
    general_section = configParser['GENERAL']
    
    BLINK_INTERVAL_NO_BOINC = general_section.get('blink_interval_no_boinc')
    BLINK_INTERVAL_NO_WORK = general_section.get('blink_interval_no_work')
    BLINK_INTERVAL_LESS_WORK = general_section.get('blink_interval_less_work')
    LED_SERVER_ENDPOINT = general_section.get('led_server_endpoint')
    LED_SERVER_TIMEOUT = general_section.getint('led_server_timeout')
    LED_PAYLOAD_LEFT_PADDING = general_section.get('led_payload_left_padding')
    LED_PAYLOAD_RIGHT_PADDING = general_section.get('led_payload_right_padding')
    LED_PAYLOAD = general_section.get('led_payload_format')
    BOINC_USAGE_THRESHOLD = general_section.getint('boinc_usage_threshold')
    SCAN_INTERVAL = general_section.getint('scan_interval')
    SSH_TIMEOUT = general_section.getint('ssh_timeout')
    
except:
    logger.critical('Could not parse configuration file. Please make sure the appropriate structure is in place!')
    raise SystemExit(2)

HEADERS = {'content-type': 'application/json'}
LED_PAYLOAD_LEFT_PADDING_LEN = len(LED_PAYLOAD_LEFT_PADDING)

psw_helper = password_helper()
boinc_hosts_array = []
current_host_no = 1

try:
    while True:
        #reading from config file
        current_host_section = configParser[f'HOST{current_host_no}']
        #name of the remote BOINC host
        current_host_name = current_host_section.get('name')
        #number of expected tasks on the remote host
        current_host_threads = current_host_section.getint('threads')
        #led number linked to the BOINC host
        current_host_led_no = current_host_section.get('led_no')
        #simulated (unreachable via network) state
        current_host_simulated = current_host_section.getboolean('simulated')
        
        ## do not read any other values for simulated hosts
        if not current_host_simulated:
            #ip address or hostname of the remote host
            current_host_ip = current_host_section.get('ip')
            #username used for the ssh connection
            current_host_username = current_host_section.get('username')
            #encrypted password of the above user - use the password utilities script to get the encrypted text
            current_host_password = psw_helper.decrypt_password(password, current_host_section.get('password'))
            #remote user under which the BOINC processes are being run
            current_host_boinc_user = current_host_section.get('boinc_user')
        else:
            current_host_ip = None
            current_host_username = None
            current_host_password = None
            current_host_boinc_user = None

        boinc_hosts_array.append(boinc_host(current_host_name, current_host_simulated, current_host_ip, current_host_username, 
                                            current_host_password, current_host_led_no, current_host_boinc_user, current_host_threads))
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
            logger.info('-----------------------------------------------')
            logger.info(f'Checking {boinc_host_entry.name}...')
            
            #add an element separator before each item
            if len(command_string) > LED_PAYLOAD_LEFT_PADDING_LEN:
                command_string += ', '
            
            if boinc_host_entry.simulated:
                logger.info('BOINC tasks are being worked on (simulated host).')
                command_string += LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', '0')
                
            else:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
                    ssh.connect(boinc_host_entry.ip, username=boinc_host_entry.username, password=boinc_host_entry.password, timeout=SSH_TIMEOUT)
                    parent_ssh_command = f'ps -u {boinc_host_entry.boinc_username} -U {boinc_host_entry.boinc_username} | grep -w boinc | wc -l'
                    logger.debug(f'Issuing parent ssh command: {parent_ssh_command}')
                    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(parent_ssh_command)
                    
                    ssh_stdin.close()
                    output = int(ssh_stdout.read().decode('utf-8').strip())
                    logger.debug(f'Parent ssh command output is: {output}')
                    
                    if output == 1:
                        logger.debug('The BOINC service is running.')
    
                        ssh_command = (f'ps -h --ppid `ps -u {boinc_host_entry.boinc_username} -U {boinc_host_entry.boinc_username}' 
                                        ' | grep -w boinc | awk \'{print $1}\'` | wc -l')
                        logger.debug(f'Issuing ssh command: {ssh_command}')
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(ssh_command)
                        ssh_stdin.close()
                        output = int(ssh_stdout.read().decode('utf-8').strip())
                        logger.debug(f'ssh command output is: {output}')
                        
                        if output > 0:
                            if output < boinc_host_entry.threads:
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
                                    
                                    #if the overall cpu usage is more than BOINC_USAGE_THRESHOLD * the number of expected BOINC threads 
                                    if output > BOINC_USAGE_THRESHOLD * boinc_host_entry.threads:
                                        logger.info('BOINC tasks are being worked on (expected cpu usage).')
                                        command_string += LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', '0')
                                    else:
                                        logger.info('BOINC tasks are being worked on (below expected cpu usage).')
                                        command_string += LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', BLINK_INTERVAL_LESS_WORK)
                                
                                else:
                                    logger.info('BOINC tasks are being worked on (below expected task count).')
                                    command_string += LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', BLINK_INTERVAL_LESS_WORK)
                                
                            else:
                                if output == boinc_host_entry.threads:
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
                    #logger.error(traceback.format_exc())
                    command_string += LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '0').replace('$led_blink', '0')
                
                finally:
                    ssh.close()
                    
        if len(boinc_hosts_array) > 0:
            logger.info('-----------------------------------------------')
        
        #ending the command string
        command_string += LED_PAYLOAD_RIGHT_PADDING
                
        logger.info('Checkup rounds complete. Updating LEDs...')
        
        logger.debug(f'Sending payload: {command_string}')
        data = json.loads(command_string)
        requests.post(LED_SERVER_ENDPOINT, json=data, headers=HEADERS, timeout=LED_SERVER_TIMEOUT)
        
        logger.info('LEDs updated.')
                
        logger.info('Sleeping until next checkup...')
        sleep(SCAN_INTERVAL)
        
except KeyboardInterrupt:
    pass
    
logger.info('Exiting boincmon service...')
