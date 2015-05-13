#
# == Class: dns::packetfilter
#
# This class configures packetfilter to only let in traffic from specified 
# IP-addresses to the dns daemon (e.g. bind, dnsmasq).
#
# == Parameters
#
# [*allow_tcp*]
#   Allow DNS requests to TCP port 53. This may be necessary for many reasons 
#   (DNSSec, zone transfers, IPv6). Valid values are 'yes' (default) and 'no'.
# [*allow_address_ipv4*]
#   An IPv4 address or subnet from which to allow connections.
# [*allow_address_ipv6*]
#   An IPv6 address or subnet from which to allow connections.
#
class dns::packetfilter
(
    $allow_tcp = 'yes',
    $allow_address_ipv4,
    $allow_address_ipv6

) inherits dns::params
{

    # Determine whether to limit access or not
    $source_v4 = $allow_address_ipv4 ? {
        'any' => undef,
        default => $allow_address_ipv4,
    }

    $source_v6 = $allow_address_ipv6 ? {
        'any' => undef,
        default => $allow_address_ipv6,
    }

    # Resource defaults
    Firewall {
        chain => 'INPUT',
        action => 'accept',
        dport => 53,
    }

    # UDP rules
    firewall { '007 ipv4 accept udp dns':
        provider => 'iptables',
        proto    => 'udp',
        source   => $source_v4,
    }

    firewall { '007 ipv6 accept udp dns':
        provider => 'ip6tables',
        proto    => 'udp',
        source   => $source_v6,
    }

    # TCP rules
    if $allow_tcp == 'yes' {
        firewall { '007 ipv4 accept tcp dns':
            provider => 'iptables',
            proto    => 'tcp',
            source   => $source_v4,
        }

        firewall { '007 ipv6 accept tcp dns':
            provider => 'ip6tables',
            proto    => 'tcp',
            source   => $source_v6,
        }
    }
}
