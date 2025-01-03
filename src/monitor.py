import logging
import requests
import re
import os
from datetime import datetime
import threading
import time

logging.basicConfig(level=logging.DEBUG)

def get_env(key, fallback):
    env = os.getenv(key, default=fallback)
    return env


def get_local_ip():
    retry_counter = 0
    while retry_counter < 50:
        try:
            response = requests.get("{}/check_ip".format(get_env("NETWATCH_COLLECTOR_URL", "https://api.netwatch.team")))
            if response.status_code == 200:
                logging.info("Got the following local IP: {}".format(response.json().get("ip")))
                return response.json().get("ip")
            else:
                logging.error(
                    "[!] Got a non 200 status code from the netwatch backend: {} with message: {}".format(response.status_code,
                                                                                                   response.text))
        except Exception as e:
            logging.error("[!] Got an exception while trying to get the local IP: {}".format(e))

        retry_counter += 1
        time.sleep(10)

    logging.error(
        "[!] The system was unable to get the local IP for {} times. Sensor can not work without local IP => Exit".format(
            retry_counter))
    exit()

def submit_attack(ip, user, password, evidence, ATTACKPOD_LOCAL_IP):
    json = {"source_ip": ip,
            "destination_ip": ATTACKPOD_LOCAL_IP,
            "username":user,
            "password":password,
            "attack_timestamp": datetime.now().isoformat(),
            "evidence":evidence,
            "attack_type": "SSH_BRUTE_FORCE",
            }

    header = {"authorization": get_env("NETWATCH_COLLECTOR_AUTHORIZATION", "")}

    retry_counter = 0
    while retry_counter < 5:
        try:
            response = requests.post("{}/add_attack".format(get_env("NETWATCH_COLLECTOR_URL", "")),
                                     json=json,
                                     headers=header)
            if response.status_code == 200:
                logging.info("Reported the following json to the netwatch collector: {}".format(json))
                return
            else:
                logging.error("[!] Got a non 200 status code from the collector: {} with message: {}".format(response.status_code, response.text))
        except Exception as e:
            logging.error("[!] Got an exception while submitting the attack to the collector: {}".format(e))

        retry_counter += 1
        time.sleep(10)

    logging.error("[!] The system was unable to submit the attack to the collector for {} times. Skipping this one!".format(retry_counter))


def run_sshd():
    while True:
        os.system("/sbin/sshd -D -E /var/log/ssh.log")


def rotate_sshd_keys():
    os.system("rm -f /etc/ssh/ssh_host_*")
    os.system("ssh-keygen -t rsa -b 2048 -f /etc/ssh/ssh_host_rsa_key")
    os.system("ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_key")
    os.system("ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_key")


if __name__ == '__main__':
    logging.info("[+] Starting NetWatch Attackpod")
    logging.info("[+] Getting local ip")

    if os.getenv("ATTACK_POD_IP") is not None:
        ATTACKPOD_LOCAL_IP = get_env("ATTACK_POD_IP","")
    else:
        ATTACKPOD_LOCAL_IP = get_local_ip()
    
    logging.info("[+] Got the local ip of {} for the AttackPod".format(ATTACKPOD_LOCAL_IP))

    logging.info("[+] Rotating SSHD Keys")
    rotate_sshd_keys()

    logging.info("[+] Starting SSHD")
    sshd_thread = threading.Thread(target=run_sshd, args=())
    sshd_thread.start()

    with open("/var/log/ssh.log", 'r') as logfile:
        logfile.seek(0, os.SEEK_END)

        ip = ""
        user = ""
        password = ""
        evidence = ""

        while True:
            # read last line of file
            line = logfile.readline()
            # sleep if file hasn't been updated
            if not line:
                time.sleep(0.1)
                continue

            logging.debug("Captured a new line from sshd: {}".format(line))
            output = re.findall("Login attempt by username '(.*)', password '(.*)', from ip '(\d.*)'", line)

            if len(output) == 1:
                # if the regex has a match it's the patched debug message

                if ip != "":
                    # If we have two matches after each other we submit the first one to not miss one, even if we don't have the evidence of the first one
                    submit_attack(ip, user, password, evidence, ATTACKPOD_LOCAL_IP)
                    ip = ""
                    user = ""
                    password = ""
                    evicence = ""

                user = output[0][0]
                password = output[0][1]
                ip = output[0][2]
            else:
                # If we don't have a regex match and we have a match of the "ip" in the line it is likely the "official" logline
                if ip in line and "Failed" in line:
                    evidence = line
                    submit_attack(ip, user, password, evidence, ATTACKPOD_LOCAL_IP)

                    ip = ""
                    user = ""
                    password = ""
                    evidence = ""
