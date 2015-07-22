rule purerequest_js_1
{
    meta:
        description = "advertising.js"
    strings:
        $match = "advertising.js"
    condition:
        $match
}

rule purerequest_js_2
{
    meta:
        description = "/js_defer."
    strings:
        $match = "/js_defer."
    condition:
        $match
}

rule purerequest_js_3
{
    meta:
        description = "what-is-my-ip.js"
    strings:
        $match = "what-is-my-ip.js"
    condition:
        $match
}

