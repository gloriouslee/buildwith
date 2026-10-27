"""Extra CMS / DXP / headless-CMS signatures, merged on top of the community set.

Names that already exist in the community data (e.g. "WordPress", "Contentful") simply get
extra rules; new names add new technologies. Same Wappalyzer rule format as signatures_martech.
"""

CMS = "CMS"
HL = "Headless CMS"
DXP = "DXP"
WEB = "Website builders"
ECOM = "Ecommerce"
DAM = "Digital asset management"

SIGNATURES = {
    # ------------------------------------------------- Enterprise / paid DXP & WCM
    "Adobe Experience Manager": {
        "cats": [CMS, DXP], "vendor": "Adobe",
        "html": [r"/content/experience-fragments/", r"/conf/[\w-]+/settings/wcm/", r"granite\.csrf", r"\bCQ\.WCM\b"],
        "headers": {"x-aem-instance": ""},
    },
    "Sitecore": {
        "cats": [CMS, DXP], "vendor": "Sitecore",
        "html": [r"/sitecore/(?:shell|service|api)/", r"/sitecore%20modules/"],
        "meta": {"generator": r"Sitecore"},
    },
    "Optimizely Content Management": {
        "cats": [CMS, DXP], "vendor": "Optimizely",
        "html": [r"/EPiServer/", r"/episerver/", r"/globalassets/\;confidence:40", r"/contentassets/\;confidence:40", r"epi-quickNavigator"],
        "cookies": {"epslanguage": "", "EPiForm_*": ""},
        "meta": {"generator": r"EPiServer|Episerver|Optimizely"},
    },
    "Kentico CMS": {
        "cats": [CMS, DXP], "vendor": "Kentico",
        "html": [r"/CMSPages/GetResource\.ashx", r"/CMSScripts/\;confidence:40", r"/getmedia/[0-9a-f-]{36}/", r"/CMSPages/\;confidence:40"],
        "cookies": {"CMSPreferredCulture": "", "CMSCsrfCookie": ""},
        "meta": {"generator": r"Kentico|Xperience"},
    },
    "Umbraco": {
        "cats": [CMS], "vendor": "Umbraco",
        "html": [r"/umbraco/", r"/App_Plugins/\;confidence:40"],
        "cookies": {"UMB_UCONTEXT": "", "UMB-XSRF-TOKEN": ""},
        "meta": {"generator": r"Umbraco"},
    },
    "Magnolia CMS": {
        "cats": [CMS, DXP], "vendor": "Magnolia",
        "html": [r"/\.resources/\;confidence:40", r"/\.imaging/", r"/magnoliaPublic/", r"/\.magnolia/"],
        "meta": {"generator": r"Magnolia"},
    },
    "Liferay": {
        "cats": [CMS, DXP], "vendor": "Liferay",
        "html": [r"Liferay\.(?:ThemeDisplay|Language|Util)", r"/c/portal/", r"/o/[\w-]+/(?:css|js)/\;confidence:40", r"/web/guest\;confidence:40"],
        "headers": {"liferay-portal": ""},
    },
    "Jahia DX": {
        "cats": [CMS, DXP], "vendor": "Jahia",
        "html": [r"/files/live/sites/", r"/modules/[\w-]+/(?:css|javascript)/"],
        "meta": {"generator": r"Jahia"},
    },
    "Squiz Matrix": {
        "cats": [CMS], "vendor": "Squiz",
        "html": [r"/__data/(?:assets|page_assets)/"],
        "meta": {"generator": r"Squiz Matrix"},
    },
    "Progress Sitefinity": {
        "cats": [CMS, DXP], "vendor": "Progress",
        "html": [r"/Sitefinity/\;confidence:40", r"/SFRes/", r"Telerik\.Sitefinity"],
        "meta": {"generator": r"Sitefinity"},
    },
    "HCL Digital Experience": {
        "cats": [CMS, DXP], "vendor": "HCL",
        "html": [r"/wps/(?:portal|wcm)/(?:myportal|connect|contenthandler)", r"/wps/wcm/connect/", r"/wps/portal/", r"/wps/themes/", r"/wps/contenthandler/"],
        "headers": {"x-powered-by": r"WebSphere Portal"},
    },
    "OpenText TeamSite": {
        "cats": [CMS], "vendor": "OpenText",
        "html": [r"/iw-cc/", r"/iw-mount/", r"/iw/cc/", r"/iw-bin/"],
    },
    "OpenText Web Experience Management": {
        "cats": [CMS, DXP], "vendor": "OpenText",
        "html": [r"/wem/(?:rest|js)/", r"opentext\.com/wem"],
        "meta": {"generator": r"OpenText"},
    },
    "dotCMS": {
        "cats": [CMS, DXP], "vendor": "dotCMS",
        "html": [r"/dA/[0-9a-f]{8}-", r"/contentAsset/(?:image|raw-data)/", r"/html/js/dojo/"],
        "meta": {"generator": r"dotCMS"},
        "headers": {"x-dot-server": ""},
    },
    "Crownpeak FirstSpirit": {
        "cats": [CMS, DXP], "vendor": "Crownpeak",
        "html": [r"/fs5(?:root|webedit)/", r"/\.?fs5webedit"],
        "meta": {"generator": r"FirstSpirit"},
    },
    "Bloomreach Experience Manager (Hippo)": {
        "cats": [CMS, DXP], "vendor": "Bloomreach",
        "html": [r"data-hippo", r"/site/(?:binaries|resources)/", r"/binaries/content/gallery/", r"<!--\s*hst:"],
    },
    "CoreMedia": {
        "cats": [CMS, DXP], "vendor": "CoreMedia",
        "html": [r"/blueprint/servlet/"],
        "meta": {"generator": r"CoreMedia"},
    },
    "Oracle WebCenter Sites": {
        "cats": [CMS, DXP], "vendor": "Oracle",
        "html": [r"/cs/Satellite", r"/cs/ContentServer"],
    },
    "Oracle WebCenter Portal": {
        "cats": [CMS], "vendor": "Oracle",
        "html": [r"/webcenter/(?:portal|faces)/", r"/webcenter/wcAuthor/"],
    },
    "SAP Commerce Cloud": {
        "cats": [ECOM, CMS], "vendor": "SAP",
        "html": [r"/_ui/(?:responsive|desktop|addons)/", r"yacceleratorstorefront", r"/medias/\?context="],
        "cookies": {"ROUTE": r"\.accstorefront"},
    },
    "SAP Commerce Cloud Spartacus": {
        "cats": [ECOM], "vendor": "SAP",
        "html": [r"<cx-storefront", r"<cx-page-layout"],
    },
    "Nuxeo": {
        "cats": [CMS, DAM], "vendor": "Hyland",
        "html": [r"/nuxeo/(?:nxthumb|nxfile|site|web|nxpath)/", r"/nuxeo/"],
    },
    "Alfresco": {
        "cats": [CMS, DAM], "vendor": "Hyland",
        "html": [r"/share/page/\;confidence:40", r"/alfresco/(?:service|s|api)/"],
    },
    "Gentics CMS": {"cats": [CMS], "vendor": "Gentics", "meta": {"generator": r"Gentics"}},
    "Ingeniux CMS": {"cats": [CMS], "vendor": "Ingeniux", "meta": {"generator": r"Ingeniux"}, "html": [r"/ingeniux/"]},
    "Brightspot": {"cats": [CMS], "html": [r"brightspotcdn\.com", r"data-brightspot"]},
    "Arc XP": {"cats": [CMS, DXP], "html": [r"arcpublishing\.com", r"/pf/resources/"]},
    "Enonic": {"cats": [CMS], "html": [r"/_/(?:image|asset|attachment|service)/\;confidence:40"]},
    "Ibexa DXP": {"cats": [CMS, DXP], "html": [r"/var/[\w-]+/storage/images/", r"ezplatform|ibexa\;confidence:40"]},
    "Microsoft SharePoint": {
        "cats": [CMS], "vendor": "Microsoft",
        "html": [r"/_layouts/15/", r"/_catalogs/masterpage/", r"/_vti_bin/"],
        "headers": {"microsoftsharepointteamservices": "", "sprequestguid": ""},
        "meta": {"generator": r"Microsoft SharePoint"},
    },
    "Acquia Cloud Platform": {
        "cats": ["PaaS", CMS], "vendor": "Acquia",
        "headers": {"x-ah-environment": "", "x-acquia-host": ""},
    },
    # ------------------------------------------------------- Headless / API-first
    "Contentful": {"cats": [HL], "html": [r"images\.ctfassets\.net", r"assets\.ctfassets\.net", r"cdn\.contentful\.com"]},
    "Contentstack": {"cats": [HL], "html": [r"(?:images|assets|cdn)\.contentstack\.(?:io|com)"]},
    "Sanity": {"cats": [HL], "html": [r"cdn\.sanity\.io"]},
    "Storyblok": {"cats": [HL], "html": [r"a\.storyblok\.com", r"storyblok-bridge"]},
    "Prismic": {"cats": [HL], "html": [r"images\.prismic\.io", r"static\.cdn\.prismic\.io"]},
    "DatoCMS": {"cats": [HL], "html": [r"www\.datocms-assets\.com"]},
    "Hygraph": {"cats": [HL], "html": [r"media\.graphassets\.com", r"[\w-]+\.hygraph\.com", r"graphassets\.com"]},
    "Kontent.ai": {"cats": [HL], "html": [r"assets-[\w-]+\.kc-usercontent\.com", r"assets\.kontent\.ai"]},
    "ButterCMS": {"cats": [HL], "html": [r"cdn\.buttercms\.com"]},
    "Builder.io": {"cats": [HL], "html": [r"cdn\.builder\.io"]},
    "Agility CMS": {"cats": [HL], "html": [r"cdn\.aglty\.io"]},
    "Cosmic": {"cats": [HL], "html": [r"imgix\.cosmicjs\.com", r"cdn\.cosmicjs\.com"]},
    "Strapi": {"cats": [HL], "headers": {"x-powered-by": r"^Strapi"}},
    "Netlify CMS": {"cats": [HL], "html": [r"netlify-identity-widget", r"/admin/config\.yml"]},
    # --------------------------------------------- Open source (stronger signals)
    "WordPress": {
        "cats": [CMS],
        "html": [r"/wp-json/", r"rel=[\"']https://api\.w\.org/"],
        "scriptSrc": [r"/wp-(?:content|includes)/"],
        "meta": {"generator": r"^WordPress"},
        "headers": {"link": r"api\.w\.org"},
    },
    "Drupal": {
        "cats": [CMS],
        "html": [r"/sites/[\w.-]+/files/", r"/core/misc/drupal\.js"],
        "headers": {"x-drupal-cache": "", "x-drupal-dynamic-cache": ""},
        "meta": {"generator": r"Drupal"},
    },
    "Joomla": {
        "cats": [CMS],
        "html": [r"/media/jui/", r"/components/com_\w+/", r"/media/system/js/"],
        "meta": {"generator": r"Joomla"},
    },
    "TYPO3 CMS": {
        "cats": [CMS],
        "html": [r"/typo3conf/", r"/typo3temp/"],
        "meta": {"generator": r"TYPO3"},
    },
    "Craft CMS": {"cats": [CMS], "headers": {"x-powered-by": r"Craft CMS"}, "cookies": {"CraftSessionId": ""}},
    "DNN": {
        "cats": [CMS],
        "html": [r"/DesktopModules/", r"/Portals/\d+/"],
        "meta": {"generator": r"DotNetNuke|DNN"},
    },
    "Concrete CMS": {
        "cats": [CMS],
        "html": [r"/concrete/(?:js|css)/"],
        "meta": {"generator": r"concrete5|Concrete CMS"},
    },
    "Pimcore": {"cats": [CMS], "headers": {"x-powered-by": r"pimcore"}},
    # --------------------------------------------------------- Website builders
    "Wix": {
        "cats": [CMS, WEB],
        "html": [r"static\.parastorage\.com", r"static\.wixstatic\.com", r"wixstatic\.com/media/"],
        "headers": {"x-wix-request-id": ""},
        "meta": {"generator": r"Wix\.com"},
    },
    "Squarespace": {"cats": [CMS, WEB], "html": [r"static1\.squarespace\.com", r"images\.squarespace-cdn\.com"],
                    "meta": {"generator": r"Squarespace"}},
    "Webflow": {"cats": [CMS, WEB], "html": [r"(?:assets|cdn\.prod)\.website-files\.com"], "meta": {"generator": r"Webflow"}},
    "Framer Sites": {"cats": [CMS, WEB], "html": [r"framerusercontent\.com"], "meta": {"generator": r"Framer"}},
    "Ghost": {"cats": [CMS], "meta": {"generator": r"^Ghost"}, "headers": {"x-powered-by": r"Ghost"}},
    "uCoz": {"cats": [CMS, WEB], "html": [r"ucoz\.(?:com|net|ru)", r"/\.s/src/"]},
    "Site123": {"cats": [CMS, WEB], "html": [r"site123\.com", r"cdn-cms\.f-static"]},
    "Ucraft": {"cats": [CMS, WEB], "html": [r"ucraft\.(?:net|com)"]},
}
