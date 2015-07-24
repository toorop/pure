rule purerequest_txt_1
{
    meta:
        description = "advertising.js"
    strings:
        $match = "advertising.js"
    condition:
        $match
}

rule purerequest_txt_2
{
    meta:
        description = "/js_defer."
    strings:
        $match = "/js_defer."
    condition:
        $match
}

rule purerequest_txt_3
{
    meta:
        description = "what-is-my-ip.js"
    strings:
        $match = "what-is-my-ip.js"
    condition:
        $match
}

rule purerequest_txt_4
{
    meta:
        description = "rrssb.min.js"
    strings:
        $match = "rrssb.min.js"
    condition:
        $match
}

rule purerequest_txt_5
{
    meta:
        description = "atrk.js"
    strings:
        $match = "atrk.js"
    condition:
        $match
}

rule purerequest_txt_6
{
    meta:
        description = "sqweb.js"
    strings:
        $match = "sqweb.js"
    condition:
        $match
}

rule purerequest_txt_7
{
    meta:
        description = "ec_omniture_s_code.js"
    strings:
        $match = "ec_omniture_s_code.js"
    condition:
        $match
}

rule purerequest_txt_8
{
    meta:
        description = "/utag.js"
    strings:
        $match = "/utag.js"
    condition:
        $match
}

rule purerequest_txt_9
{
    meta:
        description = "/quant.js"
    strings:
        $match = "/quant.js"
    condition:
        $match
}

rule purerequest_txt_10
{
    meta:
        description = "/piwik.js"
    strings:
        $match = "/piwik.js"
    condition:
        $match
}

rule purerequest_txt_11
{
    meta:
        description = "/ads.js"
    strings:
        $match = "/ads.js"
    condition:
        $match
}

rule purerequest_txt_12
{
    meta:
        description = "/advertisement.js"
    strings:
        $match = "/advertisement.js"
    condition:
        $match
}

rule purerequest_txt_13
{
    meta:
        description = "/cookie.js"
    strings:
        $match = "/cookie.js"
    condition:
        $match
}

rule purerequest_txt_14
{
    meta:
        description = "/retargeting-v2.min.js"
    strings:
        $match = "/retargeting-v2.min.js"
    condition:
        $match
}

rule purerequest_txt_15
{
    meta:
        description = "/metro-skin.js"
    strings:
        $match = "/metro-skin.js"
    condition:
        $match
}

rule purerequest_txt_16
{
    meta:
        description = "/track_display_module.js"
    strings:
        $match = "/track_display_module.js"
    condition:
        $match
}

rule purerequest_txt_17
{
    meta:
        description = ".jobaproximite.com/sites/default/files/js/"
    strings:
        $match = ".jobaproximite.com/sites/default/files/js/"
    condition:
        $match
}

rule purerequest_txt_18
{
    meta:
        description = ".linkedin.com/countserv/count/share?callback"
    strings:
        $match = ".linkedin.com/countserv/count/share?callback"
    condition:
        $match
}

rule purerequest_txt_19
{
    meta:
        description = ".pinterest.com/v1/urls/count.json"
    strings:
        $match = ".pinterest.com/v1/urls/count.json"
    condition:
        $match
}

rule purerequest_txt_20
{
    meta:
        description = ".voxmedia.com/event?"
    strings:
        $match = ".voxmedia.com/event?"
    condition:
        $match
}

