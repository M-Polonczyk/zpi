"""
This module defines Pydantic models representing the schema for pfSense configuration files.

The models are structured to closely match the XML configuration structure of pfSense, enabling
parsing, validation, and manipulation of pfSense configuration data in Python. Each class corresponds
to a specific section or element in the pfSense configuration, with fields mapped to XML tags and
attributes. Optional fields and aliasing are used to handle variations and naming differences between
XML and Python.

Key model groups include:
- System configuration (users, groups, web GUI, SSH, etc.)
- Network interfaces (WAN, LAN)
- DHCP and DHCPv6 server settings
- SNMP, diagnostics, syslog, NAT, and firewall filter rules
- IPsec VPN configuration
- Cron jobs, RRDTool, dashboard widgets, and DNS resolver (Unbound)
- Revision history, NTPD, certificates, and setup wizard state
- Installed packages and plugins
- SSH host key data

The root model, `PfSense`, aggregates all configuration sections, providing a complete representation
of a pfSense configuration file.

Example usage:

    xml_string = "...your pfSense XML config..."
    data_dict = xmltodict.parse(xml_string)
    config = PfSense(**data_dict['pfsense'])
    print(config.system.hostname)
"""

from pydantic import BaseModel, Field
from typing import Any, List, Optional, Union


class EmptyContent(BaseModel):
    pass


# System Configuration Models
class Group(BaseModel):
    name: str
    description: str
    scope: str
    gid: int
    member: Optional[Union[int, List[int]]] = None  # Can be a single int or a list of ints
    priv: Optional[str] = None


class User(BaseModel):
    name: str
    descr: Optional[str] = None
    scope: str # TODO: Add enum
    groupname: Optional[str] = None
    bcrypt_hash: str = Field(alias="bcrypt-hash")
    uid: int
    priv: Optional[str] = None
    expires: Optional[str] = None
    dashboardcolumns: Optional[int] = None
    authorizedkeys: Optional[str] = None
    ipsecpsk: Optional[str] = None


class WebGui(BaseModel):
    protocol: str
    loginautocomplete: Optional[str] = None
    ssl_certref: str = Field(alias="ssl-certref")
    port: int
    max_procs: int  # XML tag is max_procs, no hyphen
    ocsp_staple: Optional[str] = Field(alias="ocsp-staple", default=None)
    roaming: Optional[str] = None


class Bogons(BaseModel):
    interval: str


class Ssh(BaseModel):
    enable: Optional[str] = None
    sshdagentforwarding: Optional[str] = None


class System(BaseModel):
    optimization: str
    hostname: str
    domain: str
    dnsallowoverride: Optional[str] = None
    group: List[Group]
    user: List[User]
    nextuid: int
    nextgid: int
    timeservers: str
    webgui: WebGui
    disablenatreflection: Optional[str] = None
    disablesegmentationoffloading: Optional[str] = None
    disablelargereceiveoffloading: Optional[str] = None
    ipv6allow: Optional[str] = None
    maximumtableentries: Optional[int] = None
    powerd_ac_mode: str
    powerd_battery_mode: str
    powerd_normal_mode: str
    bogons: Bogons
    hn_altq_enable: Optional[str] = Field(alias="hn_altq_enable", default=None)
    already_run_config_upgrade: Optional[str] = None
    ssh: Ssh
    timezone: str
    serialspeed: int
    primaryconsole: str


# Interface Configuration Models
class InterfaceWan(BaseModel):
    enable: Optional[str] = None
    if_: str = Field(alias="if")
    descr: str
    ipaddr: str
    dhcphostname: Optional[str] = None
    alias_address: Optional[str] = Field(alias="alias-address", default=None)
    alias_subnet: Optional[str] = Field(alias="alias-subnet", default=None)  # e.g. "32"
    dhcprejectfrom: Optional[str] = None
    adv_dhcp_pt_timeout: Optional[str] = None
    adv_dhcp_pt_retry: Optional[str] = None
    adv_dhcp_pt_select_timeout: Optional[str] = None
    adv_dhcp_pt_reboot: Optional[str] = None
    adv_dhcp_pt_backoff_cutoff: Optional[str] = None
    adv_dhcp_pt_initial_interval: Optional[str] = None
    adv_dhcp_pt_values: Optional[str] = None
    adv_dhcp_send_options: Optional[str] = None
    adv_dhcp_request_options: Optional[str] = None
    adv_dhcp_required_options: Optional[str] = None
    adv_dhcp_option_modifiers: Optional[str] = None
    adv_dhcp_config_advanced: Optional[str] = None
    adv_dhcp_config_file_override: Optional[str] = None
    adv_dhcp_config_file_override_path: Optional[str] = None
    ipaddrv6: str
    dhcp6_duid: Optional[str] = Field(alias="dhcp6-duid", default=None)
    dhcp6_ia_pd_len: int = Field(alias="dhcp6-ia-pd-len")
    adv_dhcp6_prefix_selected_interface: Optional[str] = Field(
        alias="adv_dhcp6_prefix_selected_interface", default=None
    )
    spoofmac: Optional[str] = None


class InterfaceLan(BaseModel):
    enable: Optional[str] = None
    if_: str = Field(alias="if")
    # descr: Optional[str] = None # Not present in LAN example, but typical
    ipaddr: str
    subnet: str  # e.g. "24"
    ipaddrv6: Optional[str] = None
    subnetv6: Optional[str] = None
    media: Optional[str] = None
    mediaopt: Optional[str] = None
    track6_interface: Optional[str] = Field(alias="track6-interface", default=None)
    track6_prefix_id: Optional[int] = Field(alias="track6-prefix-id", default=None)
    gateway: Optional[str] = None
    gatewayv6: Optional[str] = None


class Interfaces(BaseModel):
    wan: InterfaceWan
    lan: InterfaceLan


# DHCP Server Models
class Range(BaseModel):
    from_: str = Field(alias="from")
    to: str


class DhcpdLan(BaseModel):
    range: Range
    enable: Optional[str] = None


class Dhcpd(BaseModel):
    lan: DhcpdLan


class Dhcpdv6Lan(BaseModel):
    range: Range
    ramode: str
    rapriority: str


class Dhcpdv6(BaseModel):
    lan: Dhcpdv6Lan


# SNMPD Model
class Snmpd(BaseModel):
    syslocation: Optional[str] = None
    syscontact: Optional[str] = None
    rocommunity: str


# Diagnostics Models
class IPv6Nat(BaseModel):
    ipaddr: Optional[str] = None


class Diag(BaseModel):
    ipv6nat: Optional[IPv6Nat]


# Syslog Model
class Syslog(BaseModel):
    filterdescriptions: Optional[int] = None


# NAT Models
class NatOutbound(BaseModel):
    mode: str


class Nat(BaseModel):
    outbound: NatOutbound


# Filter Rule Models
class FilterRuleSource(BaseModel):
    any: Optional[str] = None  # Presence of <any></any> often parses to None or ""
    network: Optional[str] = None


class FilterRuleDestination(BaseModel):
    any: Optional[str] = None
    network: Optional[str] = None


class FilterRuleTimestamp(BaseModel):
    time: int
    username: str


class FilterRule(BaseModel):
    id: Optional[str] = None
    tracker: str
    type: str
    interface: str
    ipprotocol: str
    tag: Optional[str] = None
    tagged: Optional[str] = None
    max: Optional[str] = None
    max_src_nodes: Optional[str] = Field(alias="max-src-nodes", default=None)
    max_src_conn: Optional[str] = Field(alias="max-src-conn", default=None)
    max_src_states: Optional[str] = Field(alias="max-src-states", default=None)
    statetimeout: Optional[str] = None
    statetype: Optional[str] = None
    os: Optional[str] = None
    protocol: Optional[str] = None
    source: FilterRuleSource
    destination: FilterRuleDestination
    descr: str
    updated: Optional[FilterRuleTimestamp] = None
    created: Optional[FilterRuleTimestamp] = None


class FilterSeparatorDetail(BaseModel):  # Renamed from FilterSeparatorWan
    # For <wan></wan> inside <separator>
    pass  # Empty as per example


class FilterSeparator(BaseModel):
    wan: Optional[Union[str, FilterSeparatorDetail]] = None  # Handles <wan></wan>


class Filter(BaseModel):
    rule: List[FilterRule]
    separator: Optional[FilterSeparator] = None


# IPsec Models
class IPSecClient(BaseModel):
    enable: Optional[str] = None
    radiusaccounting: Optional[str] = None
    user_source: str


class EncryptionAlgorithm(BaseModel):
    name: str
    keylen: int


class EncryptionItem(BaseModel):
    encryption_algorithm: EncryptionAlgorithm = Field(alias="encryption-algorithm")
    hash_algorithm: str = Field(alias="hash-algorithm")
    prf_algorithm: str = Field(alias="prf-algorithm")
    dhgroup: int


class EncryptionConfig(BaseModel):  # Parent of EncryptionItem
    item: EncryptionItem  # Example shows one; could be List[EncryptionItem]


class IPSecPhase1(BaseModel):
    ikeid: int
    iketype: str
    interface: str
    remote_gateway: Optional[str] = Field(alias="remote-gateway", default=None)
    protocol: str
    myid_type: str
    myid_data: Optional[str] = None
    peerid_type: str
    peerid_data: Optional[str] = None
    encryption: EncryptionConfig
    lifetime: int
    rekey_time: Optional[str] = None
    reauth_time: Optional[str] = None
    rand_time: Optional[str] = None
    pre_shared_key: Optional[str] = Field(alias="pre-shared-key", default=None)
    private_key: Optional[str] = Field(alias="private-key", default=None)
    certref: Optional[str] = None
    pkcs11certref: Optional[str] = None
    pkcs11pin: Optional[str] = None
    caref: Optional[str] = None
    authentication_method: str
    descr: str
    nat_traversal: str
    mobike: str
    mobile: Optional[str] = None
    startaction: Optional[str] = None
    closeaction: Optional[str] = None
    dpd_delay: Optional[int] = Field(default=None)  # XML values are "10", "5"
    dpd_maxfail: Optional[int] = Field(default=None)


class IPSecMobileKey(BaseModel):
    ident: str
    type: str
    pre_shared_key: str = Field(alias="pre-shared-key")
    ident_type: str
    pool_address: Optional[str] = None
    pool_netbits: int
    dns_address: Optional[str] = None


class Ipsec(BaseModel):
    client: IPSecClient
    phase1: List[IPSecPhase1]
    mobilekey: Union[IPSecMobileKey, List[IPSecMobileKey]]


# Cron Job Models
class CronItem(BaseModel):
    minute: str
    hour: Optional[str] = None
    mday: Optional[str] = None
    month: Optional[str] = None
    wday: Optional[str] = None
    who: str
    command: str


class Cron(BaseModel):
    item: List[CronItem]


# RRDTool Model
class Rrd(BaseModel):
    enable: Optional[str] = None


# Dashboard Widgets Model
class Widgets(BaseModel):
    sequence: str
    period: int


# Unbound DNS Resolver Model
class Unbound(BaseModel):
    enable: Optional[str] = None
    dnssec: Optional[str] = None
    active_interface: Optional[str] = None
    outgoing_interface: Optional[str] = None
    custom_options: Optional[str] = None
    hideidentity: Optional[str] = None
    hideversion: Optional[str] = None
    dnssecstripped: Optional[str] = None


# Revision History Model
class Revision(BaseModel):
    time: int
    description: str
    username: str


# NTPD (Network Time Protocol Daemon) Model
class NtpdGps(BaseModel):  # For <gps></gps>
    pass


class Ntpd(BaseModel):
    gps: Optional[Union[str, NtpdGps]] = None


# Certificate Model
class Cert(BaseModel):
    refid: str
    descr: str
    type: str
    crt: str  # Base64 encoded cert data
    prv: str  # Base64 encoded private key data


# Setup Wizard Temporary State Model
class WizardTempSystem(BaseModel):
    hostname: str
    domain: str


class WizardTemp(BaseModel):
    system: WizardTempSystem


# Installed Packages Models
class AccessListItem(BaseModel):
    type: str
    weight: int
    network: str
    users: Optional[str] = None
    sched: Optional[str] = None
    descr: str


class AccessList(BaseModel):
    item: List[AccessListItem]


class PackageConf(BaseModel):
    enabled: str
    read_only: str
    keep_backup: str
    login_protection: str
    log_successful_auth: str
    hateoas: str
    expose_sensitive_fields: str
    override_sensitive_fields: Optional[str] = None
    allow_pre_releases: str
    allowed_interfaces: Optional[str] = None
    represent_interfaces_as: str
    auth_methods: str
    ha_sync: str
    ha_sync_hosts: Optional[str] = None
    ha_sync_username: Optional[str] = None
    ha_sync_password: Optional[str] = None
    ha_sync_validate_certs: Optional[str] = None
    server_key: Optional[str] = None
    jwt_exp: int
    keys: Optional[str] = None
    access_list: AccessList


class PluginItem(BaseModel):
    type: str


class Plugins(BaseModel):
    item: List[PluginItem]  # Assuming list based on typical <item> usage


class InstalledPackage(BaseModel):
    name: str
    internal_name: str
    descr: str
    website: str
    category: str
    version: str
    configurationfile: str
    maintainer: str
    conf: PackageConf
    include_file: str
    plugins: Plugins


class Menu(BaseModel):
    name: str
    tooltiptext: str
    section: str
    url: str


class InstalledPackages(BaseModel):
    # package: List[
    #     InstalledPackage
    # ]
    # menu: List[Menu]
    package: Optional[Any]
    menu: Optional[Any]


# SSH Data (Host Keys) Model
class SSHKeyFile(BaseModel):
    filename: str
    xmldata: str  # Base64 encoded key data


class SshData(BaseModel):
    sshkeyfile: List[SSHKeyFile]


# Root pfSense Configuration Model
class PfSense(BaseModel):
    version: str
    lastchange: Optional[str] = None
    system: System
    interfaces: Interfaces
    staticroutes: Optional[Union[str, EmptyContent]] = None  # Empty tag
    dhcpd: Dhcpd
    dhcpdv6: Dhcpdv6
    snmpd: Snmpd
    diag: Diag
    syslog: Syslog
    nat: Nat
    filter: Filter
    shaper: Optional[Union[str, EmptyContent]] = None  # Empty tag
    ipsec: Ipsec
    aliases: Optional[Union[str, EmptyContent]] = None  # Empty tag
    proxyarp: Optional[Union[str, EmptyContent]] = None  # Empty tag
    cron: Cron
    wol: Optional[Union[str, EmptyContent]] = None  # Empty tag
    rrd: Rrd
    widgets: Widgets
    openvpn: Optional[Union[str, EmptyContent]] = None  # Empty tag
    dnshaper: Optional[Union[str, EmptyContent]] = None  # Empty tag
    unbound: Unbound
    vlans: Optional[Union[str, EmptyContent]] = None  # Empty tag
    qinqs: Optional[Union[str, EmptyContent]] = None  # Empty tag
    revision: Revision
    gateways: Optional[Union[str, EmptyContent]] = None  # Empty tag
    captiveportal: Optional[Union[str, EmptyContent]] = None  # Empty tag
    dnsmasq: Optional[Union[str, EmptyContent]] = None  # Empty tag
    ntpd: Ntpd
    cert: Cert  # Single main certificate for GUI, etc.
    wizardtemp: WizardTemp
    ppps: Optional[Union[str, EmptyContent]] = None  # Empty tag
    installedpackages: InstalledPackages
    sshdata: Optional[SshData] = None
