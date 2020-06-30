let DAT_redis_template = {

    'key':   "ski:aki",                 // gehashed OR encrypted?
    'value': {
        // $sts : SourceTimestamp in seconds/UTC
        // this timestamp is something like the issued (by certification body)
        // information, the certification of infrastructure component
        '$sts':               14.99,
        // $vts : ServerTimestamp in seconds/UTC
        '$vts':               15.42,
        // $nv : xsd:nonNegativeInteger, node version
        '$nv':                42
        ,
        'referringConnector': "URI",    // 0..1
        'securityProfile':    "",       // 1..1
        'extendedGuarantee':  [],       // 0..*
        'scope':              []        // 0..*
    }

};