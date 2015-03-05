#
# == Class: dns::packetfilter
#
# This class configures packetfilter to only let in traffic from specified 
# IP-addresses to the dns daemon (e.g. bind, dnsmasq).
#
class dns::packetfilter
(
    $allow_address_ipv4,
    $allow_address_ipv6

) inherits dns::params
{

    firewall { "007 ipv4 accept dns":
        provider => 'iptables',
        chain => 'INPUT',
        proto => 'udp',
        action => 'accept',
        source => $allow_address_ipv4 ? {
            'any' => undef,
            default => $allow_address_ipv4,
        },
        dport => 53,
    }

    firewall { "007 ipv6 accept dns":
        provider => 'ip6tables',
        chain => 'INPUT',
        proto => 'udp',
        action => 'accept',
        source => $allow_address_ipv6 ? {
            'any' => undef,
            default => $allow_address_ipv6,
        },
        dport => 53,
    }
}
