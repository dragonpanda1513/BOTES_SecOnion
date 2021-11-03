# Adding BOTSv1 Data to Security Onion
[Security Onion](https://github.com/Security-Onion-Solutions/securityonion) is a platform developed for endpoint threat hunting and can be deployed in a larger production environment down to a small home environment for research and training. For research and training purposes a key part is to add sample data to be able to practice hunting queries.

## Purpose
Splunk provides sample data from it's BOSS of the SOC CTF. Version 1, 2, and 3 has been published as open source, more info [here](https://www.splunk.com/en_us/blog/security/boss-of-the-soc-scoring-server-questions-and-answers-and-dataset-open-sourced-and-ready-for-download.html). The v1 data is available on [github here](https://github.com/splunk/botsv1) unfortunately it is formatted for ingestion into Splunk. 
The overall goal is to import into Security Onion and to mimic efforts that have been done in HELK platform outlined by [tvfischer](https://gist.github.com/tvfischer/fdc4a1a05613279a5685dc4db4f83fe4). As detailed by tvfischer, Sébastien Lehuédé has converted the data and done the work to ingest it into ELK. The process to covert the data and associated data and configuration files are published [here](https://botes.gitbook.io/botes-dataset/) under the label [**BOTES**](https://botes.gitbook.io/botes-dataset/). Developing this walk-through was a collaborative effort with [billy_sec]() and [cajanrubberduck](). 

## Requirements
Before proceeding, prepare your environment and have the following deployed on your instance:
- Deployed Security Onion, preferably using the Standalone or Import configuration type. Import is recommended for at home use
- Have enough space to copy the datasets and load them into the system (data sizes are discussed [here](https://botes.gitbook.io/botes-dataset/botes-elastic-bots-version))

## Process to Ingest BOTES Data
The following process will ingest the BOTES data as is. The data will be ingested via a file load performed in Logstash. That means that the data will be copied into one of the existing docker image volumes configured in so-logstash instance. 
In this ingest method, the decision was to place them in a directory called `botes` on the user Desktop `/home/<username>/Desktop` to begin with.

### Prepare your Environment
The first step is to make sure your have everything ready and all the data loaded and prepare your environment.
1. Download the data from [https://botes.gitbook.io/botes-dataset/botes-elastic-bots-version](https://botes.gitbook.io/botes-dataset/botes-elastic-bots-version), you will need the following dataset entries:
   - fgt_event
   - fgt_traffic
   - fgt_utm
   - iis
   - nessus-scan
   - stream-dhcp
   - stream-icmp
   - stream-ip
   - stream-ldap
   - stream-mapi
   - stream-sip
   - stream-snmp
   - stream-tcp
   - suricata
   - winevent-application
   - winevent-security
   - winevent-system
   - winregistry
   - xmlwineventlog-sysmon

2. Download the _Elasticsearch Index Template_ from [https://botes.gitbook.io/botes-dataset/botes-prerequisites](https://botes.gitbook.io/botes-dataset/botes-prerequisites), the file name is `template.json`

3. Download the _Logstash_ configuration files from [https://botes.gitbook.io/botes-dataset/botes-prerequisites](https://botes.gitbook.io/botes-dataset/botes-prerequisites), you will need the following conf files:
   - input-fgt_event.conf
   - input-fgt_traffic.conf
   - input-fgt_utm.conf
   - input-iis.conf
   - input-nessus-scan.conf
   - input-stream-dhcp.conf
   - input-stream-icmp.conf
   - input-stream-ip.conf
   - input-stream-ldap.conf
   - input-stream-mapi.conf
   - input-stream-sip.conf
   - input-stream-snmp.conf
   - input-stream-tcp.conf
   - input-suricata.conf
   - input-winevent-application.conf
   - input-winevent-security.conf
   - input-winevent-system.conf
   - input-winregistry.conf
   - input-winevent-sysmon.conf
   - output.conf

### Step 1: Configure Elasticsearch BOTES Template  ????
This step is to load the index into the elasticsearch instance:

    cd ~/Desktop/botes/
    curl -XPUT 'http://<helk-elasticsearch>:9200/_template/botes' \
      -H 'Content-Type: application/json' \
      -d@template.json


### Step 2: Prepare the Logstash Configuration
The logstash configuration files assume the data is in `/usr/share/logstash/botes`; while the configuration files will look for that location the data files will be located in `/nsm/logstash/`.
All logstash bind locations can be viewed in `/opt/so/saltstack/default/salt/logstash/init.sls`

#### First sub-step is to edit each INPUT configuration file
For each of the following files:
   - input-fgt_event.conf
   - input-fgt_traffic.conf
   - input-fgt_utm.conf
   - input-iis.conf
   - input-nessus-scan.conf
   - input-stream-dhcp.conf
   - input-stream-icmp.conf
   - input-stream-ip.conf
   - input-stream-ldap.conf
   - input-stream-mapi.conf
   - input-stream-sip.conf
   - input-stream-snmp.conf
   - input-stream-tcp.conf
   - input-suricata.conf
   - input-winevent-application.conf
   - input-winevent-security.conf
   - input-winevent-system.conf
   - input-winregistry.conf
   - input-winevent-sysmon.conf

Edit the following section and change the element `path` and add "botes" in the element `tags`:

**Original input-XXX.conf file**
```
input {
	file {
		path => ["/botes/data/winevent/botesv1.XmlWinEventLog-Microsoft-Windows-Sysmon-Operational.json"]
		start_position => "beginning"
		sincedb_path => "/dev/null"
		codec => "json"
		type => "WinEvent"
		tags => ["winevent-sysmon"]
	}
}
```
**_Changed_ input-XXX.conf file**
```
input {
	file {
		path => ["/usr/share/logstash/data/botes/botesv1.XmlWinEventLog-Microsoft-Windows-Sysmon-Operational.json"]
		start_position => "beginning"
		sincedb_path => "/dev/null"
		codec => "json"
		type => "WinEvent"
		tags => ["winevent-sysmon", "botes"]
	}
}
```
Repeat these changes for each of the `input-*.conf` files.

#### Second sub-step is to edit the output configuration file

Edit the output configuration file adding in the command setting the "ES" variable for the host, configure to use ssl, and rename file with the .jinja extension. The following changes need to be made:

**Original output.conf file**
```
output {
       	elasticsearch {
               	hosts => ["http://127.0.0.1:9200"]
		index => "botes-glooper"
       	}
}
```
**Changed output.conf.jinja file**
```
{%- set ES = salt['pillar.get']('elasticsearch:mainip ','') -%}
output { if "botes" in [tags]{
       	elasticsearch {
               	hosts => ["{{ ES }}"]
		index => "botes-glooper"
                template_name => "botes"
                template => "/template/botes.json"
                ssl => true
                ssl_certifcate_verification => false
       	}
    }
}
```
#### Add the configuration files to the Logstash server
Next step is to copy the configuration files to the Logstash volumes.
```
cd ~/Desktop/botes/
cp *.conf /opt/so/saltstack/local/salt/logstash/pipelines/config/custom/
```
### Step 3: Add Config locations to `manager.sls` and `search.sls`
All input paths need to be added to the `manager.sls` and the output.config.jinja path needs to be added to the `search.sls`. Both are located in `/opt/so/saltstack/default/pillar/logstash`

### Step 4: Add the Data Files

Next copy the data files into the Security Onion Logstash volume.
```
cd ~/Desktop/botes/
mkdir /nsm/logstash/botes
gzip -d *.gz
cp *.json /nsm/logstash/botes/
chown logstash *
chgrp logstash *

```

### Step 7: Restart Logstash

`so-logstash-restart`

You will need to wait a few minutes for the data to load.

### Step 6: Create an index in Kibana
Next step is to reference the index in Kibana UI. The easiest solution is to use the UI.
1. Login into your Security Onion instance with a web browser
2. Navigate to the _Management_ tab
3. Under **Kibana** select _Index Patterns_
4. Click on _Create Index Pattern_
5. In the _Index pattern_ field type `botes-*`
6. This should highlight `botes-glooper` as a match
7. Click _Next_
8. In the _Time Filter field name_ select either `@timestamp` or `event.created` or `event.start` depending on your preference
9. Click on _Create index button_

You should now be able to query the data under the _Discover_ tab. **Note** that depending on the timestamp used you may need to set your search data range window to 2016.
