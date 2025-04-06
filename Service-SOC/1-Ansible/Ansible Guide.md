# Using Wazuh W/ Ansible #

Short OP guide showing the best way to install Wazuh, connect agents through Ansible, as well as give them the proper /etc/ossec/conf options. <br>

## 1. Install Wazuh ##

Make sure a full Wazuh system is installed on one machine.  
```curl -sO https://packages.wazuh.com/4.11/wazuh-install.sh && sudo bash ./wazuh-install.sh -a```

## 2. Install Ansible ##

<details>
  <summary>Ubuntu</summary>

  ```sh
  apt-add-repository -y ppa:ansible/ansible
  pt-get update
  apt-get install ansible
  ```
</details>

<details>
  <summary>Debian</summary>

  ```sh
  echo "deb http://ppa.launchpad.net/ansible/ansible/ubuntu trusty main" | sudo tee -a /etc/apt/sources.list.d/ansible-debian.list
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 93C4A3FD7BB9C367
apt-get update
``` 
</details>

<details>
  <summary>Cent/RHEL7/Fedora</summary>

```sh
yum -y install epel-release
yum install ansible
``` 
</details>

## 3. Add the "Agent role variables" ##

```bash
cd /etc/ansible/roles
git clone --branch v4.11.2 https://github.com/wazuh/wazuh-ansible.git
```

## 4. Configure and USE ##
Use the agent_install.yaml playbook:

Make sure it is in the following dir: ```/etc/ansible/roles/wazuh-ansible/playbooks```
Also change the following:  
- hosts: wazuh-agents  
- address: 10.0.4.33 # CHANGE THIS  

Make sure each agent has a unique hostname - or else error will occur!  

CHECK THE AGENTS FIRST:  
```ansible all -m ping```  
```ansible all -m raw -a "hostname"```

Run it: ```ansible-playbook wazuh-agent.yml```  
or ```ansible-playbook -i inventory_file playbook.yml --limit group_name```
