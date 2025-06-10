import json
from pfsense import (
    fetch_pfsense_config,
    push_pfsense_config,
    load_pfsense_config_from_file,
    validate_pfsense_config,
)
from rag.generate_config import wygeneruj_zmiane_konfiguracji


def change_dhcp_range_example():
    config = load_pfsense_config_from_file("example_config.xml")
    print(f"{config.dhcpd.lan.range=}")

    # Remove crt and xml data before sending prompt
    sshdata = config.sshdata.model_copy() if config.sshdata else None
    cert = config.cert.model_copy() if config.cert else None
    config.sshdata = None
    config.cert = None

    opis = "Change the DHCP range on the LAN interface to maximum of 60 IPs"
    updated_config = wygeneruj_zmiane_konfiguracji(opis, config)
    if not updated_config:
        print("❌ Nie udało się wygenerować konfiguracji.")
        return

    print("✅ Wygenerowana zmiana:")
    print(updated_config)
    print(f"{updated_config.dhcpd.lan.range=}")

    # Restore sshdata and cert after generating the config
    updated_config.sshdata = sshdata
    updated_config.cert = cert


def main():
    # response = {
    #     "model": "deepseek-r1:latest",
    #     "created_at": "2025-06-08T18:20:22.016272278Z",
    #     "response": '{\n\n"version": "><script>alert(1)</script>",\n "system": {\n   "optimization": "<style>body{color:red}</style>"\n  ,\n   "hostname": "test"\n  , "domain": ""\n  , "group": [\n     { "name": "" , "description": "", "scope": "", "gid":0, "member": [ ] , "priv": "false" } ]\n  , "user": [],\n  "nextuid":123456,\n  "nextgid":789\n  ,"timeservers":"[\\"1.1.1.1\\"]"\n  ,"webgui": {\n     "protocol": "http",\n     "ssl-certref": "",\n     "port": 80,\n     "max_procs":4,\n     "loginautocomplete": "true",\n     "roaming": "false" }\n   , "powerd_ac_mode": "off"\n   ,"powerd_battery_mode": "disabled"\n   ,"powerd_normal_mode": "on"\n   ,"bogons": {\n        "interval": "time"\n        } , "ssh": { "enable": "false" }\n    ,"timezone": "UTC+8",\n    "serialspeed":30,\n    "primaryconsole":"1.2.3.4"\n\n }\n\n  , "interfaces": {\n     "wan": {"if": "wan", "descr": "", "ipaddr": "dhcp", "ipaddrv6": "dhcp", "dhcp6-ia-pd-len":0, "dhcp6-duid": "" },\n     "lan": { "if": "eth1", "ipaddr": "192.168.50.1/24", "subnet":"192.168.50.0", "gateway":"","gatewayv6": "" }\n  } , "dhcpd": {\n    "lan": { "range": {"from": "192.168.50.130", "to": "192.168.50.254"}, "enable": "true" }\n   }\n\n  ,"dhcpdv6": {\n\n     "lan": {\n        "range": { "from":"2001:db8::ba", "to":"2001:db8::be" } , "ramode": "disabled", "rapriority": "" }\n      }\n    , "snmpd": {"rocommunity": "public", "syscontact": "admin"}\n   ,"diag": { "ipv6nat": {"ipaddr":"2001:db8::/64"} } , "syslog": {\n        "filterdescriptions": 3\n    }\n\n  , "nat": {"outbound": {\n      "mode": "fullcone"\n     }} , "filter": {\n\n   "rule": [\n      { "tracker": "", "type": "" , "interface": "" ,"ipprotocol": "ip", "source": {\n         "any": "false" , "network": ""\n        } , "destination": {\n          "any":"true", "network":"" }\n         , "descr": "",\n        "protocol": "", "created": {\n           "time":0\n       \t, "username":"" }\n      } ]\n\n   }\n\n  ,"ipsec": { "client":{ "user_source":"false" } , "phase1": [ {\n     "ikeid":0,\n     "iketype": "",\n     "interface": ""\n   \t, "protocol": "" , "myid_type": "" , "peerid_type": "" , "encryption": { "item": {"encryption-algorithm": {\n        "name":"", "keylen":0\n    } , "hash-algorithm": ""\n      , "prf-algorithm": ""\n    \t, "dhgroup": 0} } , "lifetime": 3600,\n     "authentication_method": "" ,\n     "descr":"" , "nat_traversal": "false" , "mobike": "false", "private-key": "", "certref": ""\n\n   }] , "mobilekey": [ {\n        "ident": ""\n   \t, "type": ""\n      ,"pre-shared-key": ""\n       , "ident_type": "" , "pool_netbits":0}\n     ]\n\n   }\n\n   ,"cron": { "item": [\n        {"minute":"*","who":"www-data", "command":"/bin/sh -c \'[user]_cron.sh\'"},\n\n   \t{"minute":"1-59/5","who":"admin","command":"/bin/sh -c \'/usr/bin/php /var/www/html/pull.php\'"}\n\n   ] }\n\n  , "rrd": { "enable": "true" }\n  ,"widgets": {"sequence": "} ; --%><script>alert(1)</script> <img src=x onerror=alert(document.cookie)>" , "period":0}\n  , "unbound": {\n     "outgoing_interface": "eth1",\n     "dnssecstripped":"true"\n    } , "revision": {"time":0, "description":"" ,"username":""} , "ntpd": { "gps": "" }\n   , "cert": { "refid": "" , "descr": "", "type": "none" , "crt": "" , "prv": ""}\n    , "wizardtemp": {"system":{ "hostname":"1234567890", "domain":"" } }\n   ,"installedpackages": { "package": {} , "menu": {}}\n}\n\n  ',
    # }
    # response_data = response.get("response", "")
    # json_data = json.loads(response_data)
    # print(f"{json_data=}")
    # config = PfSense(**json_data)
    # print(f"{config.system.hostname=}")
    # print(f"{config.dhcpd=}")

    # Load from example file
    config = load_pfsense_config_from_file("example_config.xml")

    validate_pfsense_config(config)
    # Load from pfSense device
    # config = fetch_pfsense_config()

    # print(f"{config.dhcpd.lan.range=}")

    # push_pfsense_config(config=config)

    # opis = "Change the DHCP range on the LAN interface to maximum of 60 IPs"
    # updated_config = wygeneruj_zmiane_konfiguracji(opis, config)
    # if not updated_config:
    #     print("❌ Nie udało się wygenerować konfiguracji.")
    #     return

    # print("✅ Wygenerowana zmiana:")
    # print(updated_config)
    # print(f"{updated_config.dhcpd.lan.range=}")
    change_dhcp_range_example()


if __name__ == "__main__":
    main()
