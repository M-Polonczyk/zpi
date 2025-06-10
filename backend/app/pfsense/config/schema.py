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

import ipaddress
import re
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class EmptyContent(BaseModel):
    """Empty content placeholder with proper type definition for API compatibility."""

    class Config:
        extra = "ignore"

    def model_dump(self, **kwargs):
        return {}


def validate_ipv4_address(value: str | None) -> str | None:
    """Validate IPv4 address format."""
    if value is None or value == "":
        return value

    # Allow special values for DHCP
    if value.lower() in ["any", "lan", "wan", "dhcp", "pppoe", "ppp", "static", "none"]:
        return value

    try:
        ipaddress.IPv4Address(value)
        return value
    except ipaddress.AddressValueError:
        msg = f"Invalid IPv4 address: {value}"
        raise ValueError(msg)


def validate_ipv6_address(value: str | None) -> str | None:
    """Validate IPv6 address format."""
    if value is None or value == "":
        return value

    # Allow special values for DHCPv6
    if value.lower() in [
        "any",
        "lan",
        "wan",
        "dhcp6",
        "6rd",
        "6to4",
        "static",
        "none",
        "track6",
    ]:
        return value

    try:
        ipaddress.IPv6Address(value)
        return value
    except ipaddress.AddressValueError:
        msg = f"Invalid IPv6 address: {value}"
        raise ValueError(msg)


def validate_network_address(value: str | None) -> str | None:
    """Validate network address (can be IP/CIDR, hostname, or special values)."""
    if value is None or value == "":
        return value

    # Allow special network values
    special_values = ["any", "lan", "wan", "self", "(self)", "wansubnet", "lansubnet"]
    if value.lower() in special_values:
        return value

    # Check if it's a CIDR notation
    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return value
        except ipaddress.AddressValueError:
            pass

    # Check if it's a valid IP address
    try:
        ipaddress.ip_address(value)
        return value
    except ipaddress.AddressValueError:
        pass

    # Allow hostnames (basic validation)
    hostname_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    if re.match(hostname_pattern, value):
        return value

    msg = f"Invalid network address: {value}"
    raise ValueError(msg)


def validate_subnet_mask(value: str | None) -> str | None:
    """Validate subnet mask (CIDR notation or dotted decimal)."""
    if value is None or value == "":
        return value

    # CIDR notation (0-32 for IPv4, 0-128 for IPv6)
    if value.isdigit():
        cidr = int(value)
        if 0 <= cidr <= 128:  # Allow both IPv4 and IPv6 ranges
            return value
        msg = f"Invalid CIDR notation: {value}"
        raise ValueError(msg)

    # Dotted decimal notation for IPv4
    try:
        # Convert to IP address and check if it's a valid netmask
        mask = ipaddress.IPv4Address(value)
        # Check if it's a valid netmask by converting to int and checking binary pattern
        mask_int = int(mask)
        # Valid netmask should have consecutive 1s followed by consecutive 0s
        mask_bin = bin(mask_int)[2:].zfill(32)
        if "01" not in mask_bin:  # No 0 followed by 1
            return value
        msg = f"Invalid subnet mask: {value}"
        raise ValueError(msg)
    except ipaddress.AddressValueError:
        msg = f"Invalid subnet mask format: {value}"
        raise ValueError(msg)


# System Configuration Models
class Group(BaseModel):
    name: str
    description: str
    scope: str
    gid: int
    member: int | list[int] | None = None
    priv: str | None = None


class User(BaseModel):
    name: str
    descr: str | None = None
    scope: str  # TODO: Add enum
    groupname: str | None = None
    bcrypt_hash: str = Field(alias="bcrypt-hash")
    uid: int
    priv: str | None = None
    expires: str | None = None
    dashboardcolumns: int | None = None
    authorizedkeys: str | None = None
    ipsecpsk: str | None = None


class WebGui(BaseModel):
    protocol: str
    loginautocomplete: str | None = None
    ssl_certref: str = Field(alias="ssl-certref")
    port: int
    max_procs: int  # XML tag is max_procs, no hyphen
    ocsp_staple: str | None = Field(alias="ocsp-staple", default=None)
    roaming: str | None = None


class Bogons(BaseModel):
    interval: str


class Ssh(BaseModel):
    enable: str | None = None
    sshdagentforwarding: str | None = None


class System(BaseModel):
    optimization: str
    hostname: str
    domain: str
    dnsallowoverride: str | None = None
    group: list[Group]
    user: list[User]
    nextuid: int
    nextgid: int
    timeservers: str
    webgui: WebGui
    disablenatreflection: str | None = None
    disablesegmentationoffloading: str | None = None
    disablelargereceiveoffloading: str | None = None
    ipv6allow: str | None = None
    maximumtableentries: int | None = None
    powerd_ac_mode: str
    powerd_battery_mode: str
    powerd_normal_mode: str
    bogons: Bogons
    hn_altq_enable: str | None = Field(alias="hn_altq_enable", default=None)
    already_run_config_upgrade: str | None = None
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

    enable: str | None = None
    if_: str = Field(alias="if")
    descr: str
    ipaddr: str
    dhcphostname: str | None = None
    alias_address: str | None = Field(alias="alias-address", default=None)
    alias_subnet: str | None = Field(alias="alias-subnet", default=None)  # e.g. "32"
    dhcprejectfrom: str | None = None
    adv_dhcp_pt_timeout: str | None = None
    adv_dhcp_pt_retry: str | None = None
    adv_dhcp_pt_select_timeout: str | None = None
    adv_dhcp_pt_reboot: str | None = None
    adv_dhcp_pt_backoff_cutoff: str | None = None
    adv_dhcp_pt_initial_interval: str | None = None
    adv_dhcp_pt_values: str | None = None
    adv_dhcp_send_options: str | None = None
    adv_dhcp_request_options: str | None = None
    adv_dhcp_required_options: str | None = None
    adv_dhcp_option_modifiers: str | None = None
    adv_dhcp_config_advanced: str | None = None
    adv_dhcp_config_file_override: str | None = None
    adv_dhcp_config_file_override_path: str | None = None
    ipaddrv6: str
    dhcp6_duid: str | None = Field(alias="dhcp6-duid", default=None)
    dhcp6_ia_pd_len: int = Field(alias="dhcp6-ia-pd-len")
    adv_dhcp6_prefix_selected_interface: str | None = Field(
        alias="adv_dhcp6_prefix_selected_interface",
        default=None,
    )
    spoofmac: str | None = None

    @field_validator("ipaddr")
    @classmethod
    def validate_ipaddr(cls, v):
        return validate_ipv4_address(v)

    @field_validator("alias_address")
    @classmethod
    def validate_alias_address(cls, v):
        return validate_ipv4_address(v)

    @field_validator("alias_subnet")
    @classmethod
    def validate_alias_subnet(cls, v):
        return validate_subnet_mask(v)

    @field_validator("ipaddrv6")
    @classmethod
    def validate_ipaddrv6(cls, v):
        return validate_ipv6_address(v)


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

    enable: str | None = None
    if_: str = Field(alias="if")
    # descr: Optional[str] = None # Not present in LAN example, but typical
    ipaddr: str
    subnet: str  # e.g. "24"
    ipaddrv6: str | None = None
    subnetv6: str | None = None
    media: str | None = None
    mediaopt: str | None = None
    track6_interface: str | None = Field(alias="track6-interface", default=None)
    track6_prefix_id: int | None = Field(alias="track6-prefix-id", default=None)
    gateway: str | None = None
    gatewayv6: str | None = None

    @field_validator("ipaddr")
    @classmethod
    def validate_ipaddr(cls, v):
        return validate_ipv4_address(v)

    @field_validator("subnet")
    @classmethod
    def validate_subnet(cls, v):
        return validate_subnet_mask(v)

    @field_validator("ipaddrv6")
    @classmethod
    def validate_ipaddrv6(cls, v):
        return validate_ipv6_address(v)

    @field_validator("subnetv6")
    @classmethod
    def validate_subnetv6(cls, v):
        return validate_subnet_mask(v)

    @field_validator("gateway")
    @classmethod
    def validate_gateway(cls, v):
        return validate_ipv4_address(v)

    @field_validator("gatewayv6")
    @classmethod
    def validate_gatewayv6(cls, v):
        return validate_ipv6_address(v)


class Interfaces(BaseModel):
    wan: InterfaceWan
    lan: InterfaceLan


# DHCP Server Models
class Range(BaseModel):
    from_: str = Field(alias="from")
    to: str

    @field_validator("from_")
    @classmethod
    def validate_from(cls, v):
        if ":" in v:
            return validate_ipv6_address(v)
        return validate_ipv4_address(v)

    @field_validator("to")
    @classmethod
    def validate_to(cls, v):
        if ":" in v:
            return validate_ipv6_address(v)
        return validate_ipv4_address(v)


class DhcpdLan(BaseModel):
    range: Range
    defaultleasetime: int | None = None
    maxleasetime: int | None = None
    enable: str | None = None
    netmask: str | None = None
    gateway: str | None = None
    domain: str | None = None

    @field_validator("netmask")
    @classmethod
    def validate_netmask(cls, v):
        return validate_subnet_mask(v)

    @field_validator("gateway")
    @classmethod
    def validate_gateway(cls, v):
        return validate_ipv4_address(v)


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

    syslocation: str | None = None
    syscontact: str | None = None
    rocommunity: str


# Diagnostics Models
class IPv6Nat(BaseModel):
    ipaddr: str | None = None

    @field_validator("ipaddr")
    @classmethod
    def validate_ipaddr(cls, v):
        return validate_ipv6_address(v)


class Diag(BaseModel):
    ipv6nat: IPv6Nat | None


# Syslog Model
class Syslog(BaseModel):
    filterdescriptions: int | None = None


# NAT Models
class NatOutbound(BaseModel):
    mode: str


class Nat(BaseModel):
    outbound: NatOutbound


# Filter Rule Models
class FilterRuleSource(BaseModel):
    any: str | None = None  # Presence of <any></any> often parses to None or ""
    network: str | None = None

    @field_validator("network")
    @classmethod
    def validate_network(cls, v):
        return validate_network_address(v)


class FilterRuleDestination(BaseModel):
    any: str | None = None
    network: str | None = None

    @field_validator("network")
    @classmethod
    def validate_network(cls, v):
        return validate_network_address(v)


class FilterRuleTimestamp(BaseModel):
    time: int
    username: str


class FilterRule(BaseModel):
    id: str | None = None
    tracker: str
    type: str
    interface: str
    ipprotocol: str
    tag: str | None = None
    tagged: str | None = None
    max: str | None = None
    max_src_nodes: str | None = Field(alias="max-src-nodes", default=None)
    max_src_conn: str | None = Field(alias="max-src-conn", default=None)
    max_src_states: str | None = Field(alias="max-src-states", default=None)
    statetimeout: str | None = None
    statetype: str | None = None
    os: str | None = None
    protocol: str | None = None
    source: FilterRuleSource
    destination: FilterRuleDestination
    descr: str
    updated: FilterRuleTimestamp | None = None
    created: FilterRuleTimestamp | None = None


class FilterSeparatorDetail(BaseModel):  # Renamed from FilterSeparatorWan
    empty: str | None = None


class FilterSeparator(BaseModel):
    wan: str | FilterSeparatorDetail | None = None  # Handles <wan></wan>


class Filter(BaseModel):
    rule: list[FilterRule]
    separator: FilterSeparator | None = None


# IPsec Models
class IPSecClient(BaseModel):
    enable: str | None = None
    radiusaccounting: str | None = None
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
    remote_gateway: str | None = Field(alias="remote-gateway", default=None)
    protocol: str
    myid_type: str
    myid_data: str | None = None
    peerid_type: str
    peerid_data: str | None = None
    encryption: EncryptionConfig
    lifetime: int
    rekey_time: str | None = None
    reauth_time: str | None = None
    rand_time: str | None = None
    pre_shared_key: str | None = Field(alias="pre-shared-key", default=None)
    private_key: str | None = Field(alias="private-key", default=None)
    certref: str | None = None
    pkcs11certref: str | None = None
    pkcs11pin: str | None = None
    caref: str | None = None
    authentication_method: str
    descr: str
    nat_traversal: str
    mobike: str
    mobile: str | None = None
    startaction: str | None = None
    closeaction: str | None = None
    dpd_delay: int | None = Field(default=None)  # XML values are "10", "5"
    dpd_maxfail: int | None = Field(default=None)

    @field_validator("remote_gateway")
    @classmethod
    def validate_remote_gateway(cls, v):
        return validate_ipv4_address(v)


class IPSecMobileKey(BaseModel):
    ident: str
    type: str
    pre_shared_key: str = Field(alias="pre-shared-key")
    ident_type: str
    pool_address: str | None = None
    pool_netbits: int
    dns_address: str | None = None

    @field_validator("pool_address")
    @classmethod
    def validate_pool_address(cls, v):
        return validate_ipv4_address(v)

    @field_validator("dns_address")
    @classmethod
    def validate_dns_address(cls, v):
        return validate_ipv4_address(v)


class Ipsec(BaseModel):
    client: IPSecClient
    phase1: list[IPSecPhase1]
    mobilekey: IPSecMobileKey | list[IPSecMobileKey]


# Cron Job Models
class CronItem(BaseModel):
    minute: str
    hour: str | None = None
    mday: str | None = None
    month: str | None = None
    wday: str | None = None
    who: str
    command: str


class Cron(BaseModel):
    item: list[CronItem]


class Rrd(BaseModel):
    """RRDTool Model."""

    enable: str | None = None


class Widgets(BaseModel):
    """Dashboard Widgets Model."""

    sequence: str
    period: int


class Unbound(BaseModel):
    """Unbound DNS Resolver Model."""

    enable: str | None = None
    dnssec: str | None = None
    active_interface: str | None = None
    outgoing_interface: str | None = None
    custom_options: str | None = None
    hideidentity: str | None = None
    hideversion: str | None = None
    dnssecstripped: str | None = None


class Revision(BaseModel):
    """Revision History Model"""

    time: int
    description: str
    username: str


# TODO: write this model
class NtpdGps(BaseModel):
    empty: str | None = None


class Ntpd(BaseModel):
    gps: str | NtpdGps | None = None


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
    users: str | None = None
    sched: str | None = None
    descr: str

    @field_validator("network")
    @classmethod
    def validate_network(cls, v):
        return validate_network_address(v)


class AccessList(BaseModel):
    item: list[AccessListItem]


class PackageConf(BaseModel):
    enabled: str
    read_only: str
    keep_backup: str
    login_protection: str
    log_successful_auth: str
    hateoas: str
    expose_sensitive_fields: str
    override_sensitive_fields: str | None = None
    allow_pre_releases: str
    allowed_interfaces: str | None = None
    represent_interfaces_as: str
    auth_methods: str
    ha_sync: str
    ha_sync_hosts: str | None = None
    ha_sync_username: str | None = None
    ha_sync_password: str | None = None
    ha_sync_validate_certs: str | None = None
    server_key: str | None = None
    jwt_exp: int
    keys: str | None = None
    access_list: AccessList


class PluginItem(BaseModel):
    type: str


class Plugins(BaseModel):
    item: list[PluginItem]


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
    package: Any | None
    menu: Any | None


class SSHKeyFile(BaseModel):
    filename: str
    xmldata: str  # Base64 encoded key data


class SshData(BaseModel):
    sshkeyfile: list[SSHKeyFile]


class PfSenseOutput(BaseModel):
    """
    Represents the output of a pfSense configuration.

    This model is used to encapsulate the output data structure of a pfSense configuration,
    including the version, last change timestamp, and various configuration sections.
    """
    # Commented out because:
    # google.genai.errors.ClientError: 400 INVALID_ARGUMENT. 
    # {'error': {'code': 400, 'message': 'The specified schema produces a constraint that has too many states for serving.
    # Typical causes of this error are schemas with lots of text (for example, very long property or enum names),
    # schemas with long array length limits (especially when nested), or schemas using complex value matchers 
    # (for example, integers or numbers with minimum/maximum bounds or strings with complex formats like date-time)', 'status': 'INVALID_ARGUMENT'}}
    # system: System
    # interfaces: Interfaces
    staticroutes: str = ""
    dhcpd: Dhcpd
    dhcpdv6: Dhcpdv6
    snmpd: Snmpd
    diag: Diag
    syslog: Syslog
    nat: Nat
    filter: Filter
    shaper: str = ""
    ipsec: Ipsec
    aliases: str = ""
    proxyarp: str = ""
    cron: Cron
    wol: str = ""
    rrd: Rrd
    widgets: Widgets
    openvpn: str = ""
    dnshaper: str = ""
    unbound: Unbound
    vlans: str = ""
    qinqs: str = ""
    gateways: str = ""
    captiveportal: str = ""
    dnsmasq: str = ""
    ntpd: Ntpd
    ppps: str = ""


class PfSenseConfig(PfSenseOutput):
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
    lastchange: str | None = None
    system: System
    interfaces: Interfaces
    staticroutes: str | EmptyContent | None = None
    dhcpd: Dhcpd
    dhcpdv6: Dhcpdv6
    snmpd: Snmpd
    diag: Diag
    syslog: Syslog
    nat: Nat
    filter: Filter
    shaper: str | EmptyContent | None = None
    ipsec: Ipsec
    aliases: str | EmptyContent | None = None
    proxyarp: str | EmptyContent | None = None
    cron: Cron
    wol: str | EmptyContent | None = None
    rrd: Rrd
    widgets: Widgets
    openvpn: str | EmptyContent | None = None
    dnshaper: str | EmptyContent | None = None
    unbound: Unbound
    vlans: str | EmptyContent | None = None
    qinqs: str | EmptyContent | None = None
    revision: Revision
    gateways: str | EmptyContent | None = None
    captiveportal: str | EmptyContent | None = None
    dnsmasq: str | EmptyContent | None = None
    ntpd: Ntpd
    cert: Cert | None  # Single main certificate for GUI, etc.
    wizardtemp: WizardTemp
    ppps: str | EmptyContent | None = None
    installedpackages: InstalledPackages
    sshdata: SshData | None = None
