"""Curated martech / CX signatures (Wappalyzer format, categories given by name).

These are merged on top of the community signatures. Add your own here.
Rule kinds: url, html, scriptSrc, scripts, headers, cookies (supports * wildcard),
meta, dns {MX,TXT,NS,CNAME}, container (searched only inside tag-manager
containers such as GTM / Adobe Launch / Tealium), implies.
"""

ANALYTICS = "Analytics"
TAGS = "Tag managers"
MA = "Marketing automation"
CDP = "CDP / Personalization"
CMS = "CMS"
ECOM = "Ecommerce"
EMAIL = "Email / DNS"
CDN = "CDN / Hosting"
SUPPORT = "Customer support"
CONSENT = "Consent"
ADS = "Advertising"
AB = "A/B testing"
DAM = "Digital asset management"
VERIFY = "Domain verification"

SIGNATURES = {
    # ------------------------------------------------------------------ Adobe
    "Adobe Analytics": {
        "cats": [ANALYTICS], "vendor": "Adobe",
        "scriptSrc": [r"AppMeasurement(?:_Module_\w+)?(?:\.min)?\.js", r"/s_code\.js", r"omtrdc\.net", r"2o7\.net"],
        "cookies": {"s_vi": "", "s_fid": "", "s_cc": ""},
        "html": [r"\bs_account\b", r"s\.t\(\)|s\.tl\("],
        "container": [r"displayName[\"']?\s*:\s*[\"']Adobe Analytics"],
    },
    "Adobe Experience Platform Identity Service": {
        "cats": [ANALYTICS], "vendor": "Adobe",
        "scriptSrc": [r"VisitorAPI(?:\.min)?\.js", r"/visitor/"],
        "cookies": {"AMCV_*": "", "AMCVS_*": ""},
        "html": [r"Visitor\.getInstance"],
    },
    "Adobe Experience Platform Launch": {
        "cats": [TAGS], "vendor": "Adobe",
        "scriptSrc": [r"assets\.adobedtm\.com/", r"/launch-[0-9a-f]{8,}(?:-staging|-development)?(?:\.min)?\.js"],
        "html": [r"_satellite\b"],
        "container": [r"/launch-[0-9a-f]{8,}(?:-staging|-development)?(?:\.min)?\.js"],
    },
    "Adobe Experience Platform Web SDK": {
        "cats": [CDP], "vendor": "Adobe",
        "scriptSrc": [r"/alloy(?:\.min)?\.js", r"/alloy/"],
        "cookies": {"kndctr_*": ""},
        "html": [r"__alloyNS", r"\balloy\(\s*[\"']configure"],
        "container": [r"displayName[\"']?\s*:\s*[\"']Adobe Experience Platform Web SDK"],
    },
    "Adobe Experience Platform Edge Network": {
        "cats": [CDP], "vendor": "Adobe",
        "html": [r"[\w.-]+\.adobedc\.net"],
        "scriptSrc": [r"\.adobedc\.net"],
    },
    "Adobe Target": {
        "cats": [AB, CDP], "vendor": "Adobe",
        "scriptSrc": [r"/at\.js\b", r"/adobe-target", r"tt\.omtrdc\.net"],
        "cookies": {"mbox": ""},
        "html": [r"adobe\.target\b", r"mboxCreate|at-element-marker|at-body-style"],
        "container": [r"displayName[\"']?\s*:\s*[\"']Adobe Target"],
    },
    "Adobe Audience Manager": {
        "cats": [CDP], "vendor": "Adobe",
        "scriptSrc": [r"demdex\.net"],
        "html": [r"dpm\.demdex\.net"],
        "container": [r"displayName[\"']?\s*:\s*[\"']Adobe Audience Manager"],
    },
    "Adobe Client Data Layer": {
        "cats": [ANALYTICS], "vendor": "Adobe",
        "html": [r"\badobeDataLayer\b"],
    },
    "Adobe Experience Manager": {
        "cats": [CMS], "vendor": "Adobe",
        "html": [r"/etc\.clientlibs/", r"/etc/designs/[^\"'\s]+/clientlibs", r"/content/dam/", r"/libs/granite/", r"/libs/cq/"],
        "scriptSrc": [r"/etc\.clientlibs/"],
        "dns": {"CNAME": [r"adobeaemcloud\.com", r"adobecqms\.net"]},
    },
    "Magento": {
        "cats": [ECOM], "vendor": "Adobe",
        "html": [r"/static/(?:version\d+/)?frontend/", r"Magento_[A-Z]\w+"],
        "cookies": {"mage-cache-storage": "", "mage-cache-sessid": ""},
        "headers": {"x-magento-cache-debug": "", "x-magento-tags": ""},
    },
    "Marketo": {
        "cats": [MA], "vendor": "Adobe",
        "scriptSrc": [r"munchkin\.marketo\.net", r"/munchkin\.js", r"mktoForms2", r"marketo\.com/js/forms2"],
        "html": [r"Munchkin\.init", r"\bmktoForm\b", r"\bmktoForms2\b"],
        "cookies": {"_mkto_trk": ""},
        "container": [r"munchkin\.marketo\.net"],
        "dns": {"TXT": [r"mktomail\.com", r"mktdns\.com"]},
    },
    "Adobe Dynamic Media Classic": {
        "cats": [DAM], "vendor": "Adobe",
        "html": [r"scene7\.com/is/(?:image|content)/"],
    },
    "Adobe Admin Console (domain verified)": {
        "cats": [VERIFY], "vendor": "Adobe",
        "dns": {"TXT": [r"^adobe-idp-site-verification="]},
    },
    "Adobe Campaign (SPF/links)": {
        "cats": [MA], "vendor": "Adobe",
        "html": [r"/nl/jsp/m\.jsp", r"/r/\?id=[0-9a-f]+,[0-9a-f]+,[0-9a-f]+"],
        "dns": {"TXT": [r"adobecampaign|campaign\.adobe\.com"]},
    },
    # ------------------------------------------------------------- Salesforce
    "Salesforce Marketing Cloud": {
        "cats": [MA], "vendor": "Salesforce",
        "html": [r"[\w.-]*exacttarget\.com", r"[\w.-]+\.exct\.net", r"sfmc-content\.com", r"marketingcloudapis\.com", r"cloud\.[\w-]+\.(?:com|net)/[^\"'\s]*\?jb="],
        "scriptSrc": [r"exacttarget\.com", r"marketingcloudapis\.com"],
        "dns": {"TXT": [r"exacttarget\.com", r"_spf\.salesforce\.com\s.*exacttarget"]},
    },
    "Salesforce Interaction Studio": {
        "cats": [CDP], "vendor": "Salesforce",
        "scriptSrc": [r"cdn\.evergage\.com", r"\.evergage\.com/"],
    },
    "Salesforce Marketing Cloud Account Engagement": {
        "cats": [MA], "vendor": "Salesforce",
        "scriptSrc": [r"pi\.pardot\.com/pd\.js", r"cdn\.pardot\.com", r"pardot\.com"],
        "html": [r"\bpiAId\b", r"\bpiCId\b", r"go\.pardot\.com"],
        "cookies": {"pi_opt_in*": "", "visitor_id*-hash": ""},
        "dns": {"TXT": [r"^pardot\d+="]},
    },
    "Salesforce Commerce Cloud": {
        "cats": [ECOM], "vendor": "Salesforce",
        "html": [r"/on/demandware\.(?:store|static)/", r"/dw/image/v2/"],
        "scriptSrc": [r"/on/demandware\.static/"],
    },
    # The site itself is served by Experience Cloud (its own runtime assets are on the page).
    "Salesforce Experience Cloud": {
        "cats": [CMS], "vendor": "Salesforce",
        "html": [r"/s/sfsites/", r"/sfsites/l/", r"/webruntime/"],
    },
    # The site only links to a portal (dealer / partner / customer community) hosted on Experience Cloud.
    "Salesforce Experience Cloud (linked portal)": {
        "cats": ["CRM"], "vendor": "Salesforce", "relation": "linked",
        # /ESW… paths on my.site.com are the Embedded Messaging deployment, not a portal
        "html": [r"https?://[\w-]+\.my\.site\.com(?!/ESW)(?:/[\w./-]*)?", r"https?://(?!service\.)[\w-]+\.force\.com(?!/ESW|/embeddedservice)(?:/[\w./-]*)?"],
    },
    "Salesforce Web-to-Lead": {
        "cats": ["CRM"], "vendor": "Salesforce",
        "html": [r"[\w.-]*salesforce\.com/servlet/servlet\.WebToLead"],
    },
    "Salesforce Web-to-Case": {
        "cats": ["CRM", SUPPORT], "vendor": "Salesforce",
        "html": [r"[\w.-]*salesforce\.com/servlet/servlet\.WebToCase"],
    },
    "Salesforce Embedded Messaging": {
        "cats": [SUPPORT], "vendor": "Salesforce",
        "scriptSrc": [r"/ESW\w+/assets/js/bootstrap(?:\.min)?\.js"],
        "html": [r"embeddedservice_bootstrap", r"[\w-]+\.my\.salesforce-scrt\.com"],
        "container": [r"embeddedservice_bootstrap", r"salesforce-scrt\.com"],
    },
    "Salesforce Data Cloud (Web SDK)": {
        "cats": [CDP], "vendor": "Salesforce",
        "scriptSrc": [r"c360a(?:\.min)?\.js", r"cdn\.c360a\.salesforce\.com"],
    },
    "Salesforce Service Cloud": {
        "cats": [SUPPORT], "vendor": "Salesforce",
        "scriptSrc": [r"/embeddedservice/", r"service\.force\.com", r"salesforceliveagent\.com"],
        "html": [r"embedded_svc\.init\(", r"liveagent\.init\("],
    },
    "Salesforce (email sending / SPF)": {
        "cats": [EMAIL], "vendor": "Salesforce",
        "dns": {"TXT": [r"include:_spf\.salesforce\.com", r"include:[\w.]*salesforce\.com"]},
    },
    # --------------------------------------------------------------- Sitecore
    "Sitecore": {
        "cats": [CMS], "vendor": "Sitecore",
        "html": [r"/-/(?:jss)?media/"],
        "cookies": {"sc_analytics_global_cookie": "", "sc_expview": ""},
    },
    "Sitecore XM Cloud / JSS": {
        "cats": [CMS], "vendor": "Sitecore",
        "html": [r"[\w-]+\.sitecorecloud\.io", r"__JSS_STATE__", r"/sitecore/api/layout/"],
    },
    "Sitecore CDP / Personalize": {
        "cats": [CDP], "vendor": "Sitecore",
        "scriptSrc": [r"\.boxever\.com", r"sitecorecloud\.io"],
        "html": [r"\bBoxever\b", r"\._boxever_settings"],
    },
    "Sitecore Content Hub": {
        "cats": [DAM], "vendor": "Sitecore",
        "html": [r"stylelabs\.(?:cloud|io)", r"sitecorecontenthub"],
    },
    # ---------------------------------------------------------- Other martech
    "HubSpot": {
        "cats": [MA, "CRM"], "vendor": "HubSpot",
        "scriptSrc": [r"js\.hs-scripts\.com", r"js\.hsforms\.net", r"js\.hs-analytics\.net", r"js\.usemessages\.com", r"js\.hubspotfeedback\.com"],
        "html": [r"hbspt\.forms\.create", r"\b_hsq\b"],
        "cookies": {"hubspotutk": "", "__hstc": "", "__hssc": ""},
        "headers": {"x-hs-hub-id": ""},
        "meta": {"generator": r"HubSpot"},
        "dns": {"TXT": [r"_spf\.hubspotemail\.net", r"hubspot\.com"]},
    },
    "Eloqua": {
        "cats": [MA], "vendor": "Oracle",
        "scriptSrc": [r"img\d*\.en25\.com", r"eloqua\.com", r"elqCfg"],
        "html": [r"\belqSiteId\b", r"\belqCfg\b", r"\.en25\.com"],
        "cookies": {"elqCustomerGUID": ""},
    },
    "Oracle Responsys": {
        "cats": [MA], "vendor": "Oracle",
        "html": [r"\.rsys\d\.net", r"pages\.[\w.-]+/pub/sf/", r"responsys\.net"],
        "dns": {"TXT": [r"rsys\d\.net", r"responsys"]},
    },
    "Klaviyo": {
        "cats": [MA, EMAIL], "vendor": None,
        "scriptSrc": [r"static\.klaviyo\.com", r"a\.klaviyo\.com"],
        "html": [r"\b_learnq\b"],
        "cookies": {"__kla_id": ""},
    },
    "Braze": {
        "cats": [MA], "vendor": None,
        "scriptSrc": [r"js\.appboycdn\.com", r"braze(?:-web-sdk)?(?:\.min)?\.js", r"sdk\.iad-\d+\.braze\.com"],
        "html": [r"appboy\.initialize|braze\.initialize"],
    },
    "Optimizely": {
        "cats": [AB], "vendor": "Optimizely",
        "scriptSrc": [r"cdn\.optimizely\.com/(?:js|public)/", r"optimizely\.com/datafile"],
        "cookies": {"optimizelyEndUserId": ""},
        "html": [r"window\.optimizely\b"],
    },
    "Dynamic Yield": {
        "cats": [CDP, AB], "vendor": None,
        "scriptSrc": [r"cdn\.dynamicyield\.com", r"st\.dynamicyield\.com", r"dynamicyield\.com/api"],
        "cookies": {"_dycnst": "", "_dy_ses_load_seq": ""},
    },
    "Tealium": {
        "cats": [TAGS, CDP], "vendor": None,
        "scriptSrc": [r"tags\.tiqcdn\.com/utag/", r"/utag\.js"],
        "html": [r"\butag_data\b", r"utag\.view\("],
    },
    "Segment": {
        "cats": [CDP], "vendor": None,
        "scriptSrc": [r"cdn\.segment\.(?:com|io)/analytics\.js"],
        "cookies": {"ajs_anonymous_id": ""},
    },
    "mParticle": {
        "cats": [CDP], "vendor": None,
        "scriptSrc": [r"jssdkcdns\.mparticle\.com", r"mparticle\.com/js"],
    },
    "Google Tag Manager": {
        "cats": [TAGS], "vendor": "Google",
        "scriptSrc": [r"googletagmanager\.com/gtm\.js"],
        "html": [r"GTM-[A-Z0-9]{4,}"],
    },
    "Google Analytics 4": {
        "cats": [ANALYTICS], "vendor": "Google",
        "scriptSrc": [r"googletagmanager\.com/gtag/js\?id=G-"],
        "cookies": {"_ga_*": ""},
    },
    "Google Ads": {
        "cats": [ADS], "vendor": "Google",
        "scriptSrc": [r"googleadservices\.com", r"googletagmanager\.com/gtag/js\?id=AW-"],
    },
    "Facebook Pixel": {
        "cats": [ADS], "vendor": "Meta",
        "scriptSrc": [r"connect\.facebook\.net/[\w_]+/fbevents\.js"],
        "cookies": {"_fbp": ""},
    },
    "Linkedin Insight Tag": {
        "cats": [ADS], "vendor": None,
        "scriptSrc": [r"snap\.licdn\.com/li\.lms-analytics/insight"],
    },
    "TikTok Pixel": {
        "cats": [ADS], "vendor": None,
        "scriptSrc": [r"analytics\.tiktok\.com"],
    },
    "OneTrust": {
        "cats": [CONSENT], "vendor": None,
        "scriptSrc": [r"cdn\.cookielaw\.org", r"onetrust\.com"],
        "cookies": {"OptanonConsent": "", "OptanonAlertBoxClosed": ""},
    },
    "Cookiebot": {"cats": [CONSENT], "scriptSrc": [r"consent\.cookiebot\.com"]},
    "TrustArc": {"cats": [CONSENT], "scriptSrc": [r"consent\.trustarc\.com"]},
    "Usercentrics": {"cats": [CONSENT], "scriptSrc": [r"app\.usercentrics\.eu", r"usercentrics\.eu"]},
    "Hotjar": {
        "cats": [ANALYTICS],
        "scriptSrc": [r"static\.hotjar\.com"],
        "cookies": {"_hjSessionUser_*": "", "_hjid": ""},
    },
    "Microsoft Clarity": {
        "cats": [ANALYTICS], "vendor": "Microsoft",
        "scriptSrc": [r"clarity\.ms/tag"],
        "cookies": {"_clck": ""},
    },
    "Zendesk": {"cats": [SUPPORT], "scriptSrc": [r"static\.zdassets\.com", r"ekr\.zdassets\.com"],
                "dns": {"TXT": [r"zendesk\.com"]}},
    "Intercom": {"cats": [SUPPORT], "scriptSrc": [r"widget\.intercom\.io", r"js\.intercomcdn\.com"]},
    "Drift": {"cats": [SUPPORT], "scriptSrc": [r"js\.driftt\.com"]},
    "LivePerson": {"cats": [SUPPORT], "scriptSrc": [r"lpcdn\.lpsnmedia\.net"]},
    # ----------------------------------------------------- Platform / hosting
    "WordPress": {
        "cats": [CMS],
        "html": [r"/wp-content/", r"/wp-includes/"],
        "meta": {"generator": r"^WordPress"},
    },
    "Drupal": {
        "cats": [CMS],
        "headers": {"x-generator": r"Drupal"},
        "html": [r"/sites/default/files/", r"Drupal\.settings"],
        "meta": {"generator": r"^Drupal"},
    },
    "Shopify": {
        "cats": [ECOM],
        "scriptSrc": [r"cdn\.shopify\.com"],
        "headers": {"x-shopid": ""},
        "dns": {"CNAME": [r"shops\.myshopify\.com"]},
    },
    "Next.js": {
        "cats": ["Web frameworks"],
        "headers": {"x-powered-by": r"^Next\.js"},
        "html": [r"__NEXT_DATA__", r"/_next/static/"],
    },
    "ASP.NET": {
        "cats": ["Web frameworks"], "vendor": "Microsoft",
        "headers": {"x-aspnet-version": "", "x-powered-by": r"ASP\.NET"},
    },
    "Cloudflare": {
        "cats": [CDN],
        "headers": {"server": r"^cloudflare", "cf-ray": ""},
        "dns": {"NS": [r"\.ns\.cloudflare\.com$"]},
    },
    "Akamai": {
        "cats": [CDN],
        "headers": {"server": r"AkamaiGHost|AkamaiNetStorage", "x-akamai-transformed": "", "akamai-grn": ""},
        "dns": {"CNAME": [r"edgekey\.net", r"akamaiedge\.net", r"akamai\.net"]},
    },
    "Fastly": {
        "cats": [CDN],
        "headers": {"x-fastly-request-id": "", "x-served-by": r"^cache-"},
        "dns": {"CNAME": [r"fastly\.net"]},
    },
    "Amazon CloudFront": {
        "cats": [CDN], "vendor": None,
        "headers": {"x-amz-cf-id": "", "via": r"CloudFront"},
        "dns": {"CNAME": [r"cloudfront\.net"]},
    },
    "Azure Front Door": {
        "cats": [CDN], "vendor": "Microsoft",
        "headers": {"x-azure-ref": ""},
        "dns": {"CNAME": [r"azurefd\.net", r"azureedge\.net", r"trafficmanager\.net"]},
    },
    "Vercel": {"cats": [CDN], "headers": {"x-vercel-id": ""}},
    "Netlify": {"cats": [CDN], "headers": {"x-nf-request-id": ""}},
    "Imperva": {"cats": [CDN], "cookies": {"visid_incap_*": "", "incap_ses_*": ""}, "headers": {"x-iinfo": ""}},
    # ------------------------------------------------------------ Email / DNS
    "Google Workspace": {
        "cats": [EMAIL], "vendor": "Google",
        "dns": {"MX": [r"aspmx\.l\.google\.com$", r"googlemail\.com$", r"\.google\.com$"],
                "TXT": [r"include:_spf\.google\.com"]},
    },
    "Microsoft 365": {
        "cats": [EMAIL], "vendor": "Microsoft",
        "dns": {"MX": [r"mail\.protection\.outlook\.com$"],
                "TXT": [r"include:spf\.protection\.outlook\.com", r"^MS=ms\d+"]},
    },
    "Proofpoint": {"cats": [EMAIL], "dns": {"MX": [r"pphosted\.com$", r"ppe-hosted\.com$"]}},
    "Mimecast": {"cats": [EMAIL], "dns": {"MX": [r"mimecast\.com$"]}},
    "Zoho Mail": {"cats": [EMAIL], "dns": {"MX": [r"zoho\.(?:com|eu|in|com\.au)$"]}},
    "Amazon SES": {"cats": [EMAIL], "dns": {"TXT": [r"include:amazonses\.com"]}},
    "Sendgrid": {"cats": [EMAIL], "dns": {"TXT": [r"include:sendgrid\.net"]}},
    "MailChimp": {"cats": [EMAIL, MA], "dns": {"TXT": [r"servers\.mcsv\.net", r"mandrillapp\.com"]}},
    "Atlassian (domain verified)": {"cats": [VERIFY], "vendor": None, "dns": {"TXT": [r"^atlassian-domain-verification="]}},
    "Facebook (domain verified)": {"cats": [VERIFY], "vendor": "Meta", "dns": {"TXT": [r"^facebook-domain-verification="]}},
    "Google Search Console (verified)": {"cats": [VERIFY], "vendor": "Google", "dns": {"TXT": [r"^google-site-verification="]}},
    "DocuSign (domain verified)": {"cats": [VERIFY], "dns": {"TXT": [r"^docusign="]}},
    "Zoom (domain verified)": {"cats": [VERIFY], "dns": {"TXT": [r"^ZOOM_verify_"]}},
}
