#!/usr/bin/env python3
'''
@author: Winter Snowfall
@version: 2.32
@date: 28/12/2023
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
# uncomment for debugging purposes only
#import traceback

# conf file block
CONF_FILE_PATH = path.join('..', 'conf', 'boinc_host.conf')

# logging configuration block
LOG_FILE_PATH = path.join('..', 'logs', 'pi_boincmon.log')
logger_file_handler = logging.FileHandler(LOG_FILE_PATH, encoding='utf-8')
LOGGER_FORMAT = '%(asctime)s %(levelname)s >>> %(message)s'
logger_file_handler.setFormatter(logging.Formatter(LOGGER_FORMAT))
# logging level for other modules
logging.basicConfig(format=LOGGER_FORMAT, level=logging.ERROR)
logger = logging.getLogger(__name__)
# logging level defaults to INFO, but can be later modified through config file values
logger.setLevel(logging.INFO) # DEBUG, INFO, WARNING, ERROR, CRITICAL
logger.addHandler(logger_file_handler)

# CONSTANTS
HTTP_HEADERS = {'content-type': 'application/json'}
BOINC_HOST_DELIMITER = ', '

def sigterm_handler(signum, frame):
    logger.debug('Stopping boincmon due to SIGTERM...')
    
    raise SystemExit(0)

def sigint_handler(signum, frame):
    logger.debug('Stopping boincmon due to SIGINT...')
    
    raise SystemExit(0)

class boinc_host:
    
    def __init__(self, name, ip, username, password, gpu, led_no, gpu_led_no, tasks):
        self.name = name
        self.ip = ip
        self.username = username
        self.password = password
        self.gpu = gpu
        self.led_no = led_no
        self.gpu_led_no = gpu_led_no
        self.tasks = tasks

if __name__ == "__main__":
    # catch SIGTERM and exit gracefully
    signal.signal(signal.SIGTERM, sigterm_handler)
    # catch SIGINT and exit gracefully
    signal.signal(signal.SIGINT, sigint_handler)
    
    configParser = ConfigParser()
    
    try:
        configParser.read(CONF_FILE_PATH)
        
        general_section = configParser['GENERAL']
        LOGGING_LEVEL = general_section.get('logging_level').upper()
        
        #remains set to 'INFO' if none of the other valid log levels are specified
        if LOGGING_LEVEL == 'DEBUG':
            logger.setLevel(logging.DEBUG)
        elif LOGGING_LEVEL == 'WARNING':
            logger.setLevel(logging.WARNING)
        elif LOGGING_LEVEL == 'ERROR':
            logger.setLevel(logging.ERROR)
        elif LOGGING_LEVEL == 'CRITICAL':
            logger.setLevel(logging.CRITICAL)
        
        # note that the cron job mode is meant to be used primarily with ssh key authentication
        CRON_JOB_MODE = general_section.getboolean('cron_job_mode')
        SSH_COMMAND_SERVICE = general_section.get('ssh_command_service')
        BLINK_INTERVAL_NO_SERVICE = BLINK_INTERVAL_GPU_NO_TASKS = general_section.get('blink_interval_no_service')
        SSH_COMMAND_TASKS = general_section.get('ssh_command_tasks')
        SSH_COMMAND_GPU_TASKS = general_section.get('ssh_command_gpu_tasks')
        BLINK_INTERVAL_NO_TASKS = general_section.get('blink_interval_no_tasks')
        BLINK_INTERVAL_LESS_TASKS = general_section.get('blink_interval_less_tasks')
        LED_SERVER_ENDPOINT = general_section.get('led_server_endpoint')
        LED_SERVER_TIMEOUT = general_section.getint('led_server_timeout')
        LED_PAYLOAD_LEFT_PADDING = general_section.get('led_payload_left_padding')
        LED_PAYLOAD_RIGHT_PADDING = general_section.get('led_payload_right_padding')
        LED_PAYLOAD = general_section.get('led_payload_format')
        if not CRON_JOB_MODE:
            SCAN_INTERVAL = general_section.getint('scan_interval')
        SSH_KEY_AUTHENTICATION = general_section.getboolean('ssh_key_authentication')
        if SSH_KEY_AUTHENTICATION:
            SSH_PRIVATE_KEY_PATH = path.expanduser(general_section.get('ssh_private_key_path'))
        SSH_TIMEOUT = general_section.getint('ssh_timeout')
    
    except:
        logger.critical('Could not parse configuration file. Please make sure the appropriate structure is in place!')
        raise SystemExit(1)
    
    logger.info('boincmon is starting...')
    
    if SSH_KEY_AUTHENTICATION:
        # try to parse Ed25519 keys at first and fallback to RSA if that fails
        try:
            SSH_PRIVATE_KEY = paramiko.Ed25519Key.from_private_key_file(SSH_PRIVATE_KEY_PATH)
            logger.debug('Parsed SSH key using Ed25519.')
        except paramiko.ssh_exception.SSHException:
            try:
                SSH_PRIVATE_KEY = paramiko.RSAKey.from_private_key_file(SSH_PRIVATE_KEY_PATH)
                logger.debug('Parsed SSH key using RSA.')
            # paramiko supports the OpenSSH RSA private key format starting with version 2.7.1
            except paramiko.ssh_exception.SSHException:
                # can be converted with 'ssh-keygen -p -m PEM -f id_rsa'
                logger.critical('Could not parse SSH key. Either upgrade paramiko or convert your SSH key to the PEM format!')
                raise SystemExit(2)
    else:
        # read the master password from the command line
        password = input('Please enter the master password: ')
        
        if password == '':
            logger.critical('No password has been provided - exiting.')
            raise SystemExit(3)
        
        psw_helper = password_helper()
        
    boinc_hosts_array = []
    current_host_no = 1
    
    try:
        while True:
            current_host_section = configParser[f'HOST{current_host_no}']
            # name of the remote BOINC host
            current_host_name = current_host_section.get('name')
            # ip address or hostname of the remote host
            current_host_ip = current_host_section.get('ip')
            # username used for the ssh connection
            current_host_username = current_host_section.get('username')
            # no need to process passwords if we are using key based ssh authentication
            if not SSH_KEY_AUTHENTICATION:
                # encrypted password of the above user - use the password utilities script to get the encrypted text
                current_host_password = psw_helper.decrypt_password(password, current_host_section.get('password'))
            else:
                current_host_password = None
            # gpu presence and monitoring for the remote host
            current_host_gpu = current_host_section.getboolean('gpu')
            # LED number linked to the BOINC host's overall task state
            current_host_led_no = current_host_section.get('led_no')
            # LED number linked to the BOINC host's gpu task state
            if current_host_gpu:
                current_host_gpu_led_no = current_host_section.get('gpu_led_no')
            else:
                current_host_gpu_led_no = None
            # number of expected tasks on the remote host
            current_host_tasks = current_host_section.getint('tasks')
            
            boinc_hosts_array.append(boinc_host(current_host_name, current_host_ip, current_host_username, current_host_password,
                                                current_host_gpu, current_host_led_no, current_host_gpu_led_no, current_host_tasks))
            current_host_no += 1
    
    except KeyError:
        logger.info(f'BOINC host info parsing complete. Read {current_host_no - 1} entries.')
        
    except:
        logger.critical('Could not parse BOINC host entries. Please make sure the appropriate structure is in place!')
        raise SystemExit(4)
    
    loopRunner = True
    
    try:
        while loopRunner:
            logger.info('Starting checkup round...')
            # turn on the update status routine
            try:
                on_status_routine = json.loads(''.join((LED_PAYLOAD_LEFT_PADDING, 
                                                        LED_PAYLOAD.replace('$led_no', '0').replace('$led_state', '1').replace('$led_blink', '0'), 
                                                        LED_PAYLOAD_RIGHT_PADDING)))
                requests.post(LED_SERVER_ENDPOINT, json=on_status_routine, headers=HTTP_HEADERS, timeout=LED_SERVER_TIMEOUT)
            except:
                logger.warning(f'Update status routine failed - unable to connect to the LED server.')
                
            boinc_host_commands = []
            
            logger.info('***********************************************************')
            
            for boinc_host_entry in boinc_hosts_array:
                logger.info(f'Checking {boinc_host_entry.name}...')
                
                with paramiko.SSHClient() as ssh:
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    try:
                        if SSH_KEY_AUTHENTICATION:
                            ssh.connect(boinc_host_entry.ip, username=boinc_host_entry.username, pkey=SSH_PRIVATE_KEY, timeout=SSH_TIMEOUT)
                        else:
                            ssh.connect(boinc_host_entry.ip, username=boinc_host_entry.username, password=boinc_host_entry.password, timeout=SSH_TIMEOUT)
                        logger.debug(f'Issuing BOINC service ssh command: {SSH_COMMAND_SERVICE}')
                        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(SSH_COMMAND_SERVICE)
                        
                        ssh_stdin.close()
                        output = int(ssh_stdout.read().decode('utf-8'))
                        logger.debug(f'BOINC service ssh command output is: {output}')
                        
                        if output == 1:
                            logger.debug('The BOINC service is running.')
                            
                            logger.debug(f'Issuing BOINC tasks ssh command: {SSH_COMMAND_TASKS}')
                            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(SSH_COMMAND_TASKS)
                            ssh_stdin.close()
                            output = int(ssh_stdout.read().decode('utf-8'))
                            logger.debug(f'BOINC tasks ssh command output is: {output}')
                            
                            if output > 0:
                                if output < boinc_host_entry.tasks:
                                    logger.info('BOINC tasks are being worked on (below expected task count).')
                                    boinc_host_commands.append(LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', BLINK_INTERVAL_LESS_TASKS))
                                
                                else:
                                    if output == boinc_host_entry.tasks:
                                        logger.info('BOINC tasks are being worked on (expected task count).')
                                        boinc_host_commands.append(LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', '0'))
                                    else:
                                        logger.warning('BOINC tasks are being worked on (more than expected task count).')
                                        boinc_host_commands.append(LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', '0'))
                            
                            else:
                                logger.info('No BOINC tasks are being worked on.')
                                boinc_host_commands.append(LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', BLINK_INTERVAL_NO_TASKS))
                                
                            if boinc_host_entry.gpu:
                                logger.debug(f'Issuing BOINC GPU tasks ssh command: {SSH_COMMAND_GPU_TASKS}')
                                ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(SSH_COMMAND_GPU_TASKS)
                                ssh_stdin.close()
                                output = int(ssh_stdout.read().decode('utf-8'))
                                logger.debug(f'BOINC GPU tasks ssh command output is: {output}')
                                
                                if output > 0:
                                    if output == 1:
                                        logger.info('BOINC GPU tasks are being worked on (expected task count).')
                                        boinc_host_commands.append(LED_PAYLOAD.replace('$led_no', boinc_host_entry.gpu_led_no).replace('$led_state', '1').replace('$led_blink', '0'))
                                    else:
                                        logger.warning('BOINC GPU tasks are being worked on (more than expected task count).')
                                        boinc_host_commands.append(LED_PAYLOAD.replace('$led_no', boinc_host_entry.gpu_led_no).replace('$led_state', '1').replace('$led_blink', '0'))
                                else:
                                    logger.info('No BOINC GPU tasks are being worked on.')
                                    boinc_host_commands.append(LED_PAYLOAD.replace('$led_no', boinc_host_entry.gpu_led_no).replace('$led_state', '1').replace('$led_blink', BLINK_INTERVAL_GPU_NO_TASKS))
                        
                        else:
                            logger.info('The BOINC service is not running.')
                            boinc_host_commands.append(LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '1').replace('$led_blink', BLINK_INTERVAL_NO_SERVICE))
                    
                    except paramiko.ssh_exception.NoValidConnectionsError:
                        logger.warning('The server could not be reached.')
                        boinc_host_commands.append(LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '0').replace('$led_blink', '0'))
                    
                    except paramiko.ssh_exception.SSHException:
                        logger.warning('The server returned an SSH connection error.')
                        boinc_host_commands.append(LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '0').replace('$led_blink', '0'))
                    
                    except:
                        logger.error(f'Error occured during checkup - server may be down or experiencing issues.')
                        # uncomment for debugging purposes only
                        #logger.error(traceback.format_exc())
                        boinc_host_commands.append(LED_PAYLOAD.replace('$led_no', boinc_host_entry.led_no).replace('$led_state', '0').replace('$led_blink', '0'))
            
            logger.info('***********************************************************')
            
            logger.info('Checkup round complete. Updating LEDs...')
            
            try:
                data = json.loads(''.join((LED_PAYLOAD_LEFT_PADDING, 
                                           BOINC_HOST_DELIMITER.join(boinc_host_commands), 
                                           LED_PAYLOAD_RIGHT_PADDING)))
                requests.post(LED_SERVER_ENDPOINT, json=data, headers=HTTP_HEADERS, timeout=LED_SERVER_TIMEOUT)
                
                logger.info('LEDs updated.')
            except:
                logger.warning(f'LEDs update failed - unable to connect to the LED server.')
            
            if CRON_JOB_MODE:
                logger.info('Cron job mode enabled - boincmon will now exit.')
                loopRunner = False
            else:
                logger.info('Sleeping until next checkup...')
                sleep(SCAN_INTERVAL)
    
    except SystemExit:
        logger.info('Stopping boincmon service...')
    
    logger.info('boincmon service stopped.')
