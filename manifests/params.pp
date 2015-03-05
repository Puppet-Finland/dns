#
# == Class: dns::params
#
# Defines some variables based on the operating system
#
class dns::params {

    case $::kernel {
        'Linux': {
            # Nothing here atm
        }
        default: {
            fail("Unsupported OS: ${::osfamily}")
        }
    }
}
