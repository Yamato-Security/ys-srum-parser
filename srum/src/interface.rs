//! Network interfaces: an `InterfaceLuid` holds the interface's type (its
//! IANA ifType, `IF_TYPE_*` in Windows' ipifcons.h) in its top 16 bits.

/// The interface type an `InterfaceLuid` holds.
#[must_use]
pub fn interface_type(luid: i64) -> u16 {
    (luid as u64 >> 48) as u16
}

/// The `IF_TYPE_*` name of an interface type (as SrumECmd names them), or
/// `None` for one ipifcons.h does not define.
#[must_use]
pub fn interface_type_name(if_type: u16) -> Option<&'static str> {
    let index = usize::from(if_type).checked_sub(1)?;
    if let Some(name) = NAMES.get(index) {
        return Some(name);
    }
    Some(match if_type {
        237 => "IF_TYPE_IEEE80216_WMAN",
        243 => "IF_TYPE_WWANPP",
        244 => "IF_TYPE_WWANPP2",
        _ => return None,
    })
}

/// `IF_TYPE_*` 1 to 145.
const NAMES: [&str; 145] = [
    "IF_TYPE_OTHER",
    "IF_TYPE_REGULAR_1822",
    "IF_TYPE_HDH_1822",
    "IF_TYPE_DDN_X25",
    "IF_TYPE_RFC877_X25",
    "IF_TYPE_ETHERNET_CSMACD",
    "IF_TYPE_IS088023_CSMACD",
    "IF_TYPE_ISO88024_TOKENBUS",
    "IF_TYPE_ISO88025_TOKENRING",
    "IF_TYPE_ISO88026_MAN",
    "IF_TYPE_STARLAN",
    "IF_TYPE_PROTEON_10MBIT",
    "IF_TYPE_PROTEON_80MBIT",
    "IF_TYPE_HYPERCHANNEL",
    "IF_TYPE_FDDI",
    "IF_TYPE_LAP_B",
    "IF_TYPE_SDLC",
    "IF_TYPE_DS1",
    "IF_TYPE_E1",
    "IF_TYPE_BASIC_ISDN",
    "IF_TYPE_PRIMARY_ISDN",
    "IF_TYPE_PROP_POINT2POINT_SERIAL",
    "IF_TYPE_PPP",
    "IF_TYPE_SOFTWARE_LOOPBACK",
    "IF_TYPE_EON",
    "IF_TYPE_ETHERNET_3MBIT",
    "IF_TYPE_NSIP",
    "IF_TYPE_SLIP",
    "IF_TYPE_ULTRA",
    "IF_TYPE_DS3",
    "IF_TYPE_SIP",
    "IF_TYPE_FRAMERELAY",
    "IF_TYPE_RS232",
    "IF_TYPE_PARA",
    "IF_TYPE_ARCNET",
    "IF_TYPE_ARCNET_PLUS",
    "IF_TYPE_ATM",
    "IF_TYPE_MIO_X25",
    "IF_TYPE_SONET",
    "IF_TYPE_X25_PLE",
    "IF_TYPE_ISO88022_LLC",
    "IF_TYPE_LOCALTALK",
    "IF_TYPE_SMDS_DXI",
    "IF_TYPE_FRAMERELAY_SERVICE",
    "IF_TYPE_V35",
    "IF_TYPE_HSSI",
    "IF_TYPE_HIPPI",
    "IF_TYPE_MODEM",
    "IF_TYPE_AAL5",
    "IF_TYPE_SONET_PATH",
    "IF_TYPE_SONET_VT",
    "IF_TYPE_SMDS_ICIP",
    "IF_TYPE_PROP_VIRTUAL",
    "IF_TYPE_PROP_MULTIPLEXOR",
    "IF_TYPE_IEEE80212",
    "IF_TYPE_FIBRECHANNEL",
    "IF_TYPE_HIPPIINTERFACE",
    "IF_TYPE_FRAMERELAY_INTERCONNECT",
    "IF_TYPE_AFLANE_8023",
    "IF_TYPE_AFLANE_8025",
    "IF_TYPE_CCTEMUL",
    "IF_TYPE_FASTETHER",
    "IF_TYPE_ISDN",
    "IF_TYPE_V11",
    "IF_TYPE_V36",
    "IF_TYPE_G703_64K",
    "IF_TYPE_G703_2MB",
    "IF_TYPE_QLLC",
    "IF_TYPE_FASTETHER_FX",
    "IF_TYPE_CHANNEL",
    "IF_TYPE_IEEE80211",
    "IF_TYPE_IBM370PARCHAN",
    "IF_TYPE_ESCON",
    "IF_TYPE_DLSW",
    "IF_TYPE_ISDN_S",
    "IF_TYPE_ISDN_U",
    "IF_TYPE_LAP_D",
    "IF_TYPE_IPSWITCH",
    "IF_TYPE_RSRB",
    "IF_TYPE_ATM_LOGICAL",
    "IF_TYPE_DS0",
    "IF_TYPE_DS0_BUNDLE",
    "IF_TYPE_BSC",
    "IF_TYPE_ASYNC",
    "IF_TYPE_CNR",
    "IF_TYPE_ISO88025R_DTR",
    "IF_TYPE_EPLRS",
    "IF_TYPE_ARAP",
    "IF_TYPE_PROP_CNLS",
    "IF_TYPE_HOSTPAD",
    "IF_TYPE_TERMPAD",
    "IF_TYPE_FRAMERELAY_MPI",
    "IF_TYPE_X213",
    "IF_TYPE_ADSL",
    "IF_TYPE_RADSL",
    "IF_TYPE_SDSL",
    "IF_TYPE_VDSL",
    "IF_TYPE_ISO88025_CRFPRINT",
    "IF_TYPE_MYRINET",
    "IF_TYPE_VOICE_EM",
    "IF_TYPE_VOICE_FXO",
    "IF_TYPE_VOICE_FXS",
    "IF_TYPE_VOICE_ENCAP",
    "IF_TYPE_VOICE_OVERIP",
    "IF_TYPE_ATM_DXI",
    "IF_TYPE_ATM_FUNI",
    "IF_TYPE_ATM_IMA",
    "IF_TYPE_PPPMULTILINKBUNDLE",
    "IF_TYPE_IPOVER_CDLC",
    "IF_TYPE_IPOVER_CLAW",
    "IF_TYPE_STACKTOSTACK",
    "IF_TYPE_VIRTUALIPADDRESS",
    "IF_TYPE_MPC",
    "IF_TYPE_IPOVER_ATM",
    "IF_TYPE_ISO88025_FIBER",
    "IF_TYPE_TDLC",
    "IF_TYPE_GIGABITETHERNET",
    "IF_TYPE_HDLC",
    "IF_TYPE_LAP_F",
    "IF_TYPE_V37",
    "IF_TYPE_X25_MLP",
    "IF_TYPE_X25_HUNTGROUP",
    "IF_TYPE_TRANSPHDLC",
    "IF_TYPE_INTERLEAVE",
    "IF_TYPE_FAST",
    "IF_TYPE_IP",
    "IF_TYPE_DOCSCABLE_MACLAYER",
    "IF_TYPE_DOCSCABLE_DOWNSTREAM",
    "IF_TYPE_DOCSCABLE_UPSTREAM",
    "IF_TYPE_A12MPPSWITCH",
    "IF_TYPE_TUNNEL",
    "IF_TYPE_COFFEE",
    "IF_TYPE_CES",
    "IF_TYPE_ATM_SUBINTERFACE",
    "IF_TYPE_L2_VLAN",
    "IF_TYPE_L3_IPVLAN",
    "IF_TYPE_L3_IPXVLAN",
    "IF_TYPE_DIGITALPOWERLINE",
    "IF_TYPE_MEDIAMAILOVERIP",
    "IF_TYPE_DTM",
    "IF_TYPE_DCN",
    "IF_TYPE_IPFORWARD",
    "IF_TYPE_MSDSL",
    "IF_TYPE_IEEE1394",
    "IF_TYPE_RECEIVE_ONLY",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_types_from_luids() {
        // a LUID from the Windows 10 SRUM samples: type 6, Ethernet
        assert_eq!(interface_type(1_689_399_632_855_040), 6);
        assert_eq!(interface_type_name(6), Some("IF_TYPE_ETHERNET_CSMACD"));
        assert_eq!(interface_type_name(71), Some("IF_TYPE_IEEE80211"));
        assert_eq!(interface_type_name(145), Some("IF_TYPE_RECEIVE_ONLY"));
        assert_eq!(interface_type_name(243), Some("IF_TYPE_WWANPP"));
        assert_eq!(interface_type_name(0), None);
        assert_eq!(interface_type_name(200), None);
        assert_eq!(interface_type(-1), 0xffff);
    }
}
