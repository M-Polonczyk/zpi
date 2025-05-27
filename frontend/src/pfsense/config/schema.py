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
    data_dict = xmltodict.parse(xml_string, force_list=("user", "group", "staticmap"))
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
    member: Optional[Union[int, List[int]]] = None
    priv: Optional[str] = None


class User(BaseModel):
    name: str
    descr: Optional[str] = None
    scope: str  # TODO: Add enum
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
    """
    Represents the configuration schema for a WAN interface in pfSense.

    Attributes:
        enable (Optional[str]): Indicates if the interface is enabled.
        if_ (str): The interface identifier (aliased as "if").
        descr (str): Description of the interface.
        ipaddr (str): IPv4 address assigned to the interface.
        dhcphostname (Optional[str]): DHCP hostname for the interface.
        alias_address (Optional[str]): Alias IPv4 address (aliased as "alias-address").
        alias_subnet (Optional[str]): Alias subnet mask (aliased as "alias-subnet", e.g., "32").
        dhcprejectfrom (Optional[str]): List of DHCP servers to reject.
        ipaddrv6 (str): IPv6 address assigned to the interface.
        dhcp6_duid (Optional[str]): DHCPv6 DUID (aliased as "dhcp6-duid").
        dhcp6_ia_pd_len (int): DHCPv6 IA_PD prefix length (aliased as "dhcp6-ia-pd-len").
        spoofmac (Optional[str]): MAC address to spoof on the interface.
    """

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
    """
    Represents the configuration schema for a LAN interface in pfSense.

    Attributes:
        enable (Optional[str]): Indicates if the interface is enabled.
        if_ (str): The interface identifier (aliased from "if").
        ipaddr (str): The IPv4 address assigned to the interface.
        subnet (str): The IPv4 subnet mask in CIDR notation (e.g., "24").
        ipaddrv6 (Optional[str]): The IPv6 address assigned to the interface.
        subnetv6 (Optional[str]): The IPv6 subnet mask in CIDR notation.
        media (Optional[str]): The media type for the interface (e.g., "1000baseT").
        mediaopt (Optional[str]): Media options for the interface.
        track6_interface (Optional[str]): The interface to track for IPv6 (aliased from "track6-interface").
        track6_prefix_id (Optional[int]): The prefix ID for IPv6 tracking (aliased from "track6-prefix-id").
        gateway (Optional[str]): The IPv4 gateway for the interface.
        gatewayv6 (Optional[str]): The IPv6 gateway for the interface.
    """

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
    """
    SNMP (Simple Network Management Protocol) is a protocol used for monitoring and managing network devices.

    In pfSense, the SNMP daemon allows external systems to collect information and statistics about the firewall,
    such as interface status, traffic counters, and system health.
    """

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


class Rrd(BaseModel):
    """RRDTool Model."""

    enable: Optional[str] = None


class Widgets(BaseModel):
    """Dashboard Widgets Model."""

    sequence: str
    period: int


class Unbound(BaseModel):
    """Unbound DNS Resolver Model."""

    enable: Optional[str] = None
    dnssec: Optional[str] = None
    active_interface: Optional[str] = None
    outgoing_interface: Optional[str] = None
    custom_options: Optional[str] = None
    hideidentity: Optional[str] = None
    hideversion: Optional[str] = None
    dnssecstripped: Optional[str] = None


class Revision(BaseModel):
    """Revision History Model"""

    time: int
    description: str
    username: str


# TODO: write this model
class NtpdGps(BaseModel):
    pass


class Ntpd(BaseModel):
    gps: Optional[Union[str, NtpdGps]] = None


class Cert(BaseModel):
    """
    Represents a certificate configuration.

    Attributes:
        refid (str): Unique reference identifier for the certificate.
        descr (str): Description of the certificate.
        type (str): Type of the certificate (e.g., 'CA', 'server', 'user').
        crt (str): Base64 encoded certificate data.
        prv (str): Base64 encoded private key data.
    """

    refid: str
    descr: str
    type: str
    crt: str
    prv: str


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
    item: List[PluginItem]


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
    # TODO: Resolve InstalledPackages model problems
    # package: List[
    #     InstalledPackage
    # ]
    # menu: List[Menu]
    package: Optional[Any]
    menu: Optional[Any]


class SSHKeyFile(BaseModel):
    filename: str
    xmldata: str  # Base64 encoded key data


class SshData(BaseModel):
    sshkeyfile: List[SSHKeyFile]


class PfSense(BaseModel):
    """
    PfSense configuration schema model.

    This model represents the structure of a pfSense configuration file, encapsulating
    all the settings defined in the pfSense ecosystem.

    Attributes:
        version (str): The configuration version.
        lastchange (Optional[str]): Timestamp or identifier of the last configuration change.
        system (System): System-level configuration.
        interfaces (Interfaces): Network interfaces configuration.
        staticroutes (Optional[Union[str, EmptyContent]]): Static routes configuration or empty.
        dhcpd (Dhcpd): DHCPv4 server configuration.
        dhcpdv6 (Dhcpdv6): DHCPv6 server configuration.
        snmpd (Snmpd): Simple Network Management Protocol daemon configuration.
        diag (Diag): Diagnostics configuration.
        syslog (Syslog): System logging configuration.
        nat (Nat): Network Address Translation configuration.
        filter (Filter): Firewall filter configuration.
        shaper (Optional[Union[str, EmptyContent]]): Traffic shaper configuration or empty.
        ipsec (Ipsec): IPsec VPN configuration.
        aliases (Optional[Union[str, EmptyContent]]): Aliases configuration or empty.
        proxyarp (Optional[Union[str, EmptyContent]]): Proxy ARP configuration or empty.
        cron (Cron): Cron jobs configuration.
        wol (Optional[Union[str, EmptyContent]]): Wake-on-LAN configuration or empty.
        rrd (Rrd): Round Robin Database, used for time-series data configuration.
        widgets (Widgets): Dashboard widgets configuration.
        openvpn (Optional[Union[str, EmptyContent]]): OpenVPN configuration or empty.
        dnshaper (Optional[Union[str, EmptyContent]]): DNS shaper configuration or empty.
        unbound (Unbound): Unbound DNS resolver configuration.
        vlans (Optional[Union[str, EmptyContent]]): Virtual LANs configuration or empty.
        qinqs (Optional[Union[str, EmptyContent]]): QinQ VLAN configuration or empty.
        revision (Revision): Configuration revision information.
        gateways (Optional[Union[str, EmptyContent]]): Gateways configuration or empty.
        captiveportal (Optional[Union[str, EmptyContent]]): Captive portal configuration or empty.
        dnsmasq (Optional[Union[str, EmptyContent]]): Dnsmasq (DNS forwarder, DHCP server, and TFTP server) configuration or empty.
        ntpd (Ntpd): NTP daemon configuration.
        cert (Cert): Main certificate for GUI and other services.
        wizardtemp (WizardTemp): Temporary wizard data.
        ppps (Optional[Union[str, EmptyContent]]): Point-to-Point Protocols configuration or empty.
        installedpackages (InstalledPackages): READ ONLY! Installed packages configuration.
        sshdata (Optional[SshData]): SSH-related configuration data.
    """

    version: str
    lastchange: Optional[str] = None
    system: System
    interfaces: Interfaces
    staticroutes: Optional[Union[str, EmptyContent]] = None
    dhcpd: Dhcpd
    dhcpdv6: Dhcpdv6
    snmpd: Snmpd
    diag: Diag
    syslog: Syslog
    nat: Nat
    filter: Filter
    shaper: Optional[Union[str, EmptyContent]] = None
    ipsec: Ipsec
    aliases: Optional[Union[str, EmptyContent]] = None
    proxyarp: Optional[Union[str, EmptyContent]] = None
    cron: Cron
    wol: Optional[Union[str, EmptyContent]] = None
    rrd: Rrd
    widgets: Widgets
    openvpn: Optional[Union[str, EmptyContent]] = None
    dnshaper: Optional[Union[str, EmptyContent]] = None
    unbound: Unbound
    vlans: Optional[Union[str, EmptyContent]] = None
    qinqs: Optional[Union[str, EmptyContent]] = None
    revision: Revision
    gateways: Optional[Union[str, EmptyContent]] = None
    captiveportal: Optional[Union[str, EmptyContent]] = None
    dnsmasq: Optional[Union[str, EmptyContent]] = None
    ntpd: Ntpd
    cert: Cert  # Single main certificate for GUI, etc.
    wizardtemp: WizardTemp
    ppps: Optional[Union[str, EmptyContent]] = None
    installedpackages: InstalledPackages
    sshdata: Optional[SshData] = None
