from urllib.parse import urlparse, parse_qs
import Levenshtein
import re
import math
import tldextract
from datetime import datetime
from .brands import COMMON_BRANDS


# ============================================
# Helper function for safe string handling
# ============================================
def safe_str(s):
    """Convert any value to string safely"""
    if s is None:
        return ""
    if isinstance(s, str):
        return s
    return str(s)


# ============================================
# 🔴 1.1 TYPOSQUATTING PATTERNS (100+ variations)
# ============================================

# Character substitution patterns (leet speak)
CHAR_SUBSTITUTIONS = {
    'a': ['4', '@', 'а', 'á', 'à', 'â', 'ã', 'ä', 'å', 'α'],
    'b': ['8', '6', 'ь', 'β', 'Б', 'b'],
    'c': ['(', '<', '¢', 'с', '©', 'ç', 'ć', 'č'],
    'd': ['ԁ', 'ɗ', 'đ', 'ď', 'δ'],
    'e': ['3', '€', 'é', 'è', 'ê', 'ë', 'ę', 'ė', 'ē', 'ε'],
    'f': ['ƒ', 'ғ', 'φ'],
    'g': ['9', '6', 'ğ', 'ģ', 'ġ', 'γ'],
    'h': ['һ', 'ħ', 'н', 'ђ', 'ћ'],
    'i': ['1', '!', '|', 'ɪ', 'í', 'ì', 'î', 'ï', 'į', 'ī', 'ι'],
    'j': ['ј', 'ʝ', 'ϳ', 'ј'],
    'k': ['κ', 'к', 'ќ', 'ķ', 'ĸ'],
    'l': ['1', '|', 'l', 'ӏ', 'ℓ', 'ł', 'ļ', 'ľ'],
    'm': ['м', 'ϻ', 'ṃ', 'ṁ'],
    'n': ['п', 'η', 'ή', 'ń', 'ņ', 'ň', 'ñ'],
    'o': ['0', 'ο', 'о', 'σ', 'ø', 'œ', 'ō', 'ŏ', 'ő'],
    'p': ['ρ', 'р', 'þ', 'ƥ'],
    'q': ['9', 'գ', 'զ'],
    'r': ['я', 'г', 'ř', 'ŕ', 'ŗ', 'я'],
    's': ['5', '$', 'ѕ', 'ś', 'ŝ', 'ş', 'š', 'ș', 'ς'],
    't': ['7', 'τ', 'т', 'ţ', 'ť', 'ț', 'ƭ'],
    'u': ['υ', 'μ', 'ú', 'ù', 'û', 'ü', 'ů', 'ű', 'ū', 'ư'],
    'v': ['ν', 'v', 'ѵ', '٧'],
    'w': ['ѡ', 'ώ', 'ŵ'],
    'x': ['×', 'х', 'χ', 'ҳ'],
    'y': ['γ', 'у', 'ý', 'ÿ', 'ŷ', 'ў'],
    'z': ['2', 'ζ', 'ż', 'ž', 'ź'],
}

# Common brand misspellings (expanded)
COMMON_TYPOS = {
    # Google
    'google': ['goggle', 'googel', 'gogle', 'googl', 'g00gle', 'go0gle', 'gooogle', 'goog1e', 'googIe',
               'googIe', 'g o o g l e', 'googlee', 'goog le', 'g oogle', 'go ogle', 'goo gle', 'goog le',
               'gúgľ', 'göögle', 'gøøgle', 'gσσgle', 'gσσgle', 'gооgle', 'g00gl3', 'g0ogl3', 'gøøglē',
               # Missing letters
               'gogle', 'googl', 'gogle', 'goole', 'gogle', 'ggole', 'googe', 'goole',
               'ggle', 'gool', 'gogl', 'goge', 'gole', 'ggle', 'goge',
               # Extra letters
               'gooogle', 'googgle', 'ggoogle', 'gooogle', 'gooogle', 'googlee', 'googlle',
               'googlee', 'gooogle', 'googole', 'googgel', 'gooogle', 'googele',
               # Transposed letters
               'goolge', 'gogole', 'googel', 'glooge', 'golge', 'gogle', 'goegl',
               'gooegl', 'goleg', 'ggole', 'gogole', 'gooegl',
               # Shortened versions
               'ggl', 'gog', 'gge', 'gle', 'gool', 'goog', 'gogle', 'gogle',
               ],

    # Facebook
    'facebook': ['facebok', 'faceboook', 'fasebook', 'faceb00k', 'fac ebook', 'face book', 'f acebook',
                 'faсebооk', 'facebοοk', 'fасеbооk', 'fасеbооk', 'fаcеbооk', 'fаcеbооk', 'fасеbооk',
                 'faceb0ok', 'faceb0οk', 'faceb00k', 'faseb00k', 'phejsbuk', 'フェイスブック',
                 # Missing letters
                 'facebok', 'facbook', 'fcebook', 'acebook', 'febook', 'facbook',
                 'faceboo', 'faceboo', 'fcebook', 'acebook', 'febook', 'facbok',
                 'fcebok', 'acebok', 'febok', 'facbo', 'fcebo', 'acebo',
                 # Extra letters
                 'faceboook', 'faceboock', 'faceb0ok', 'faceebook', 'ffacebook',
                 'facebookk', 'facebooke', 'facebookk', 'faceboook', 'faceebook',
                 'ffacebook', 'facebookk', 'facebooke', 'faceboock', 'facebooc',
                 # Shortened versions
                 'fb', 'fbook', 'faceb', 'facer', 'faces',
                 ],

    # Amazon
    'amazon': ['amzon', 'amazan', 'amazn', 'amazoon', 'amaz0n', 'amazοn', 'аmаzоn', 'аmаzοn', 'аmаzоn',
               'amaz0n', 'amazón', 'amazòn', 'amazön', 'amazøn', 'amazơŋ', 'amaz0n', 'amaz-on', 'amaz.on',
               'āmāzōń', 'åmåzøń', 'αmαzση', 'αmαζση', 'αmαzοη',
               # Missing letters
               'amzon', 'amazn', 'amzn', 'amazo', 'mazon', 'azon', 'amzn', 'amzon',
               'amazn', 'amzo', 'amzn', 'amaz', 'azon', 'mzon', 'amz',
               # Extra letters
               'amazoon', 'amazzon', 'amazone', 'amazonn', 'aamazon', 'amazono',
               'amazoon', 'amazzon', 'amazone', 'amazonn', 'aamazon', 'amazono',
               # Shortened versions
               'amzn', 'amz', 'amaz', 'azon',
               ],

    # PayPal
    'paypal': ['paypl', 'paypall', 'paypa1', 'pay-pal', 'pay pal', 'pаypаl', 'pаypаl', 'pаypаl', 'pаypаl',
               'pаypаl', 'paypаl', 'pаypal', 'paypаl', 'paypαl', 'paypΔl', 'paypΛl', 'paypål', 'paypæl',
               'paypāł', 'payp@l', 'payp4l', 'p@yp@l', 'p4yp4l', 'pаypаl', 'pаypаl',
               # Missing letters
               'paypl', 'pypal', 'payal', 'ppal', 'pypal', 'payl', 'ppal', 'pypal',
               'payl', 'ppl', 'pyp', 'pal', 'pay', 'ppal', 'pypal', 'payl',
               # Extra letters
               'paypall', 'payypal', 'ppaypal', 'paypalp', 'paypall', 'payypal',
               'ppaypal', 'paypalp', 'paypall', 'payypal', 'ppaypal', 'paypalp',
               # Shortened versions
               'pp', 'pal', 'pay', 'pyp', 'ppl',
               ],

    # Apple
    'apple': ['appple', 'aple', 'appl', 'appIe', 'app1e', 'appIe', 'äpple', 'æpple', 'åpple', 'αpple',
              'appłē', 'appłè', 'appłé', 'appłê', 'appłë', 'appłė', 'appļe', 'appļē', 'appļè', 'appļé',
              # Missing letters
              'aple', 'appl', 'ape', 'ple', 'apl', 'ppe', 'app', 'aple', 'appl',
              'ape', 'ple', 'apl', 'ppe', 'app', 'aple', 'appl', 'ape', 'ple',
              # Extra letters
              'appple', 'appple', 'appple', 'appleee', 'aapple', 'appple',
              'appplee', 'appple', 'appple', 'appple', 'appplee', 'aapple',
              # Shortened versions
              'apl', 'app', 'ap', 'ple',
              ],

    # Microsoft
    'microsoft': ['microsft', 'microsfot', 'micrsoft', 'micros0ft', 'microsοft', 'microsoftt', 'micr0s0ft',
                  'micrσsσft', 'micrøsøft', 'micrösöft', 'micrōsōft', 'mīcrōsōft', 'mïcrösöft', 'mįcrøsøft',
                  # Missing letters
                  'microsft', 'micrsoft', 'microft', 'micsoft', 'microsoft', 'microft',
                  'micsoft', 'mcrosoft', 'microsoft', 'microft', 'micsoft', 'mcrosoft',
                  # Extra letters
                  'microssoft', 'microssoft', 'microssoft', 'microssoft', 'microsoftt',
                  'microssoft', 'microssoft', 'microssoft', 'microsoftt', 'microssoft',
                  # Shortened versions
                  'msft', 'micro', 'soft', 'ms',
                  ],

    # Netflix
    'netflix': ['netflic', 'netflx', 'netf1ix', 'nеtflіх', 'nеtflіx', 'nеtfliх', 'nєtfliх', 'nєtflix',
                'nētflīx', 'nêtflîx', 'nëtflïx', 'nętflįx', 'ŋetfliχ', 'ηετfℓιχ', 'ηετƒℓιχ',
                # Missing letters
                'netflx', 'netflic', 'netfix', 'netflx', 'netflic', 'netfix',
                'netflx', 'netflic', 'netfix', 'netflx', 'netflic', 'netfix',
                # Extra letters
                'netflixx', 'netfliix', 'netflick', 'netflics', 'netfliks',
                # Shortened versions
                'nflx', 'ntflx', 'net', 'flix',
                ],

    # Instagram
    'instagram': ['instgram', 'instagrm', '1nstagram', 'instagrаm', 'instagrαm', 'instagrām', 'instagrâm',
                  'instagräm', 'instagræm', 'instagrãm', 'instagråm', 'instagrăm', 'instagrаm', 'instagrΛm',
                  # Missing letters
                  'instgram', 'instagrm', 'instgram', 'instagrm', 'instgram', 'instagrm',
                  'istagram', 'instgram', 'instagrm', 'istagram', 'instgram', 'instagrm',
                  # Shortened versions
                  'ig', 'insta', 'gram', 'inst',
                  ],

    # WhatsApp
    'whatsapp': ['whatsap', 'watsapp', 'whatsappp', 'whаtsаpp', 'whαtsαpp', 'whātsāpp', 'whâtsâpp',
                 'whätsäpp', 'whætsæpp', 'whãtsãpp', 'whåtsåpp', 'whătsăpp', 'whаtsаpp', 'whαtsαpp',
                 # Missing letters
                 'whatsap', 'watsapp', 'whatsap', 'watsapp', 'whatsap', 'watsapp',
                 'whatapp', 'whtsapp', 'wattsapp', 'whasapp', 'whatsap', 'watsapp',
                 # Shortened versions
                 'wa', 'whats', 'wapp', 'wsapp',
                 ],

    # Twitter/X
    'twitter': ['twiter', 'twtter', 'tw1tter', 'twittеr', 'twittєr', 'twittēr', 'twittêr', 'twittër',
                'twittėr', 'twittęr', 'twittεr', 'twittэr', 'twittэя', 'twittэя',
                # Missing letters
                'twiter', 'twtter', 'twiter', 'twtter', 'twiter', 'twtter',
                'twiiter', 'twittr', 'twitt', 'twiier', 'twitt', 'twittr',
                # X/Twitter variants
                'x', 'xx', 'xxx', 'twiter', 'xcom', 'x.com', 'twitterx', 'xtwitter',
                # Shortened versions
                'tw', 'twt', 'tweet', 'twtr',
                ],

    # LinkedIn
    'linkedin': ['linkdin', 'linkedn', 'l1nked1n', 'linkеdіn', 'linkєdіn', 'linkēdīn', 'linkêdîn',
                 'linkëdïn', 'linkėdįn', 'linkεdιn', 'linkэdин', 'linkэdин',
                 # Missing letters
                 'linkdin', 'linkedn', 'linkdin', 'linkedn', 'linkdin', 'linkedn',
                 'linkein', 'linkin', 'linkdn', 'linked', 'linkin', 'linkdn',
                 # Shortened versions
                 'lnkd', 'linked', 'link', 'li',
                 ],

    # Snapchat
    'snapchat': ['snapcat', 'snapchаt', 'snapchαt', 'snapchāt', 'snapchât', 'snapchät', 'snapchæt',
                 # Missing letters
                 'snapcat', 'snapchat', 'snapcat', 'snapchat', 'snapcat', 'snapchat',
                 'snapct', 'snachat', 'snapca', 'snapch', 'snapca', 'snapch',
                 # Shortened versions
                 'snap', 'chat', 'sc',
                 ],

    # TikTok
    'tiktok': ['tikok', 't1kt0k', 'tіktоk', 'tīktōk', 'tîktôk', 'tïktök', 'tįktøk', 'tiķtök',
               # Missing letters
               'tikok', 'titok', 'tikok', 'titok', 'tikok', 'titok',
               'tiktk', 'tikto', 'tito', 'tikt', 'tikto', 'tikt',
               # Shortened versions
               'tt', 'tik', 'tok', 'tktk',
               ],

    # YouTube
    'youtube': ['youtub', 'y0utube', 'yоutubе', 'yōutūbē', 'yôutûbê', 'yöutübë', 'yøutūbē', 'yσutυbε',
                # Missing letters
                'youtub', 'yotube', 'youtbe', 'youtub', 'yotube', 'youtbe',
                'yutube', 'youube', 'youtbe', 'youtub', 'yotube', 'youtbe',
                # Shortened versions
                'yt', 'tube', 'you', 'utube',
                ],

    # Gmail
    'gmail': ['gmai1', 'gmаіl', 'gmαіl', 'gmāīl', 'gmâîl', 'gmäïl', 'gmæįl', 'gmεіl',
              # Missing letters
              'gmai', 'gmal', 'gmil', 'gail', 'mail', 'gmai', 'gmal', 'gmil',
              'gail', 'mail', 'gmai', 'gmal', 'gmil', 'gail', 'mail',
              # Shortened versions
              'gm', 'gml', 'mail',
              ],

    # Hotmail
    'hotmail': ['hotmai1', 'hоtmаіl', 'hōtmāīl', 'hôtmâîl', 'hötmäïl', 'høtmæįl', 'hσtmαιl',
                # Missing letters
                'hotmai', 'hotmil', 'hotmal', 'otmail', 'htmail', 'hotmai', 'hotmil',
                'hotmal', 'otmail', 'htmail', 'hotmai', 'hotmil', 'hotmal',
                # Shortened versions
                'hot', 'mail', 'hm',
                ],

    # Yahoo
    'yahoo': ['yahоо', 'yahσσ', 'yahōō', 'yahôô', 'yahöö', 'yahøø', 'yahœœ',
              # Missing letters
              'yahо', 'yaho', 'yahо', 'yaho', 'yahо', 'yaho', 'yahо', 'yaho',
              'yahо', 'yaho', 'yahо', 'yaho', 'yahо', 'yaho', 'yahо', 'yaho',
              # Shortened versions
              'yh', 'yho', 'yah',
              ],
}

# ============================================
# 🔴 1.2 SUSPICIOUS TLDs (100+)
# ============================================

SUSPICIOUS_TLDS = [
    # Free/Cheap TLDs (often used for phishing)
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'online', 'site',
    'website', 'space', 'tech', 'store', 'shop', 'bid', 'trade', 'webcam',
    'review', 'stream', 'download', 'country', 'kim', 'men', 'loan', 'date',
    'racing', 'win', 'xin', 'mom', 'lol', 'vip', 'live', 'pro', 'info',

    # Country TLDs abused for phishing
    'ru', 'cn', 'tk', 'cf', 'ga', 'ml', 'gq', 'pw', 'cc', 'ws', 'tv',
    'cm', 'co', 'uk', 'de', 'nl', 'br', 'in', 'jp', 'fr', 'au', 'ca',
    'it', 'es', 'pl', 'tr', 'tw', 'vn', 'kr', 'id', 'th', 'my', 'ph',

    # New gTLDs often abused
    'xyz', 'club', 'online', 'site', 'website', 'space', 'tech', 'store',
    'shop', 'bid', 'trade', 'webcam', 'review', 'stream', 'download',
    'country', 'kim', 'men', 'loan', 'date', 'racing', 'win', 'xin',
    'mom', 'lol', 'vip', 'live', 'pro', 'info', 'buzz', 'host', 'press',

    # Suspicious TLDs
    'work', 'party', 'gdn', 'moe', 'click', 'link', 'help', 'support',
    'global', 'uno', 'ooo', 'cricket', 'science', 'faith', 'рус', 'рф',
    '中文网', '在线', '公司', '网络', '手机', '移动', '商标', '购物',

    # High-risk TLDs
    'rest', 'adult', 'porn', 'sex', 'dating', 'date', 'love', 'wedding',
    'cam', 'work', 'jobs', 'rent', 'sale', 'market', 'biz', 'loan',

    # Free domain TLDs
    'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'tv', 'ws', 'bid',
    'trade', 'webcam', 'review', 'stream', 'download', 'country',

    # Additional suspicious TLDs
    'science', 'faith', 'church', 'mom', 'lol', 'gay', 'xxx', 'adult',
    'pics', 'pictures', 'photo', 'foto', 'photography', 'gallery',
    'video', 'tube', 'tv', 'stream', 'live', 'radio', 'music',
]

# Safe TLDs (for reference)
SAFE_TLDS = [
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'io', 'co', 'uk',
    'de', 'jp', 'fr', 'au', 'ca', 'in', 'ac.in', 'edu.in', 'gov.in',
    'nic.in', 'co.in', 'net.in', 'org.in', 'res.in', 'eu', 'us', 'ch',
    'at', 'be', 'dk', 'fi', 'gr', 'ie', 'il', 'is', 'lt', 'lu', 'lv',
    'mt', 'no', 'nz', 'pl', 'pt', 'se', 'sg', 'za', 'hr', 'hu', 'cz',
]

# ============================================
# 🔴 2.2 URL SHORTENERS (100+)
# ============================================

URL_SHORTENERS = [
    # Popular shorteners
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 't.co', 'tr.im', 'rb.gy', 'cutt.ly', 'short.link',
    'tiny.one', 'shorte.st', 'bc.vc', 'soo.gd', 's2r.co', 'db.tt',
    'qr.ae', 'cur.lv', 'shorturl.at', 'tiny.cc', 'bitly.com',

    # More shorteners
    '1url.com', '2.gp', '2doc.net', '2url.com', '3.ly', '4url.cc',
    '7.ly', 'a.co', 'a.gg', 'aka.ms', 'amzn.to', 'app.link', 'ars.to',
    'bbc.in', 'binged.it', 'bit.do', 'bitly.is', 'buzurl.com', 'cbsn.ws',
    'chan.sr', 'cli.gs', 'cort.as', 'dai.ly', 'db.tt', 'disq.us',
    'dlvr.it', 'doi.org', 'drib.ps', 'dropbox.link', 'eepurl.com',
    'engt.co', 'fanp.me', 'fb.me', 'flic.kr', 'fly2.io', 'fon.gs',
    'food.news', 'for.tn', 'form.jotform.com', 'fwd4.me', 'g.co',
    'git.io', 'gl.am', 'go.aws', 'go.usa.gov', 'goo.gl', 'hellotxt.com',
    'href.li', 'huffp.st', 'ift.tt', 'ig.me', 'imgur.io', 'inltest.com',
    'is.gd', 'j.mp', 'kask.us', 'kl.am', 'knlr.com', 'korta.nu',
    'kr3w.de', 'l9k.net', 'lc.chat', 'lc-s.co', 'leadtools.co',
    'li.srr.li', 'line.me', 'lnkd.in', 'loopt.us', 'lp4.io', 'mag.nu',
    'mash.to', 'mcaf.ee', 'migre.me', 'mkl.st', 'moourl.com', 'myloc.me',
    'n9.cl', 'nets.is', 'ni.nf', 'np1u.com', 'nsfw.in', 'nx-s.com',
    'nyti.ms', 'o-x.fr', 'on.fb.me', 'on.mktw.net', 'on.wsj.com',
    'onforb.es', 'opr.as', 'ow.ly', 'p.ost.im', 'p2purl.com', 'p6l.org',
    'parg.co', 'pb.st', 'pd.oglaszamy.net', 'ph.dog', 'phinf.ly',
    'pich.in', 'pin.st', 'pixel.mx', 'plu.sh', 'pn.tv', 'po.st',
    'poprl.com', 'pp.gg', 'ppst.cc', 'ps.gg', 'qr.net', 'qte.me',
    'qxp.cz', 'rb.gy', 'rcl.gr', 'reut.rs', 'ri.ms', 'rickroll.it',
    'rover.ebay.com', 's.coop', 's4c.in', 's7.addthis.com', 's7.addthis.com',
    'safe.mn', 'sco.lt', 'sh.st', 'shar.es', 'short.to', 'shortlinks.co.uk',
    'shorturl.com', 'shout.lt', 'show.co', 'shrt.st', 'shrten.com',
    'shrunkin.com', 'shy.si', 'sify.com', 'sk.gy', 'slate.me', 'smallr.com',
    'snipurl.com', 'snurl.com', 'sp2.ro', 'spn.sr', 'sptfy.com', 'srs.li',
    'su.pr', 't.cn', 't.co', 't.ly', 't.me', 't3n.de', 't7v.de', 'ta.gd',
    'tabzi.com', 'techmeme.com', 'theweek.com', 'thk.vn', 'thud.ws',
    'tiny.pl', 'tiny.yt', 'tinyarrows.com', 'tinylink.in', 'tinyuri.ca',
    'tinyurl.com', 'tinyurl.mobi', 'tldrify.com', 'tms.telekom.com',
    'tnij.org', 'tny.com', 'tny.im', 'to.ly', 'togoto.us', 'tr.im',
    'track.flexlinks.com', 'track.visitors.com', 'trib.al', 'trunc.it',
    'tweetburner.com', 'twet.me', 'twit.ac', 'twitclicks.com', 'twitterpan.com',
    'twittr.com', 'twlr.me', 'twurl.nl', 'u.bb', 'u.to', 'u.zdn.vn',
    'ub0.cc', 'ulu.lu', 'unlc.us', 'ur1.ca', 'url.ca', 'url.co.uk',
    'url4.eu', 'urlenco.de', 'urlzen.com', 'ust.to', 'uym.us', 'v.gd',
    'vgn.me', 'vzturl.com', 'wapo.st', 'wasd.com', 'wp.me', 'wpeg.co',
    'wtc.la', 'x.co', 'x.nu', 'x.se', 'x10.mx', 'x2c.eu', 'x2c.eumx',
    'x2c.la', 'xaddr.com', 'xclicks.net', 'xgd.in', 'xip.li', 'xl8.eu',
    'xn--allhistorie-u8b.no', 'xn--allmter-vxa.ch', 'xn--allmter-vxa.info',
    'xpl.fun', 'xpr.me', 'xr.com', 'xrl.in', 'xrl.us', 'xt3.us', 'xurl.es',
    'xzb.cc', 'y2u.be', 'yago.me', 'yatuc.com', 'ye.pe', 'yeb.io',
    'yep.it', 'yestur.com', 'yfrog.com', 'youtu.be', 'youtube.googleapis.com',
    'yro.sk', 'yweb.com', 'yyc.co', 'z0.de', 'z0r.de', 'z7c.de',
    'za.gl', 'zad.ir', 'zap.buzz', 'zapto.org', 'zazzle.com', 'zb.gg',
    'zd.net', 'zee.gl', 'zen.co', 'zeos.in', 'zer0.it', 'zero.eu',
    'zeus.io', 'zh.my', 'zhongwen.com', 'zip.net', 'zip.li', 'zipurl.com',
    'zite.to', 'zn.my', 'znl.to', 'znp.com', 'zo.ee', 'zo.gl',
    'zoo.co', 'zoom.us', 'zoop.eu', 'zoot.com', 'zoot.it', 'zoot.ro',
    'zoot.us', 'zor.org', 'zpag.es', 'zpr.io', 'zpxx.nl', 'zqr.com',
    'zrl.co', 'zrl.in', 'zrp.gr', 'zrp.pl', 'zto.my', 'zty.my', 'zud.me',
    'zul.me', 'zur.me', 'zurl.me', 'zurl.org', 'zws.im', 'zx2.net',
    'zxc.ru', 'zxq.net', 'zy.am', 'zy.me', 'zynga.com', 'zz.ht',
    'zz.vc', 'zzz.com', 'zzz.gg', 'zzz.lv', 'zzz.rs', 'zzz.si',
]

# ============================================
# 🔴 3.2 SUSPICIOUS FILE EXTENSIONS (100+)
# ============================================

SUSPICIOUS_EXTENSIONS = [
    # Executable files
    '.exe', '.msi', '.bat', '.cmd', '.sh', '.bin', '.run', '.com',
    '.scr', '.cpl', '.gadget', '.msc', '.wsf', '.vbs', '.ps1', '.psm1',
    '.psd1', '.ps1xml', '.pssc', '.msh', '.msh1', '.msh2', '.mshxml',
    '.msh1xml', '.msh2xml', '.reg', '.vb', '.vbe', '.js', '.jse',
    '.jar', '.class', '.app', '.application', '.pif', '.vbscript',

    # Compressed files (often used to hide malware)
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.z', '.lz',
    '.lzma', '.lzo', '.rz', '.sz', '.dz', '.cbz', '.cbr', '.cb7',
    '.zipx', '.tgz', '.tbz2', '.tlz', '.txz', '.tzst', '.iso', '.dmg',
    '.img', '.vhd', '.vhdx', '.vmdk', '.ova', '.ovf', '.vbox',

    # Office documents with macros
    '.doc', '.docx', '.docm', '.dot', '.dotx', '.dotm', '.xls', '.xlsx',
    '.xlsm', '.xlsb', '.xlt', '.xltx', '.xltm', '.ppt', '.pptx', '.pptm',
    '.pot', '.potx', '.potm', '.pps', '.ppsx', '.ppsm', '.sldx', '.sldm',

    # PDF and other documents
    '.pdf', '.ps', '.eps', '.prn', '.svg', '.xml', '.xps', '.oxps',

    # Script files
    '.php', '.php3', '.php4', '.php5', '.php7', '.phtml', '.asp',
    '.aspx', '.asax', '.ascx', '.ashx', '.asmx', '.axd', '.cfm',
    '.cfml', '.cgi', '.pl', '.pm', '.py', '.pyc', '.pyo', '.pyd',
    '.rb', '.rbw', '.rhtml', '.erb', '.jsp', '.jspx', '.jspa',
    '.jspf', '.jsw', '.jsv', '.jtml', '.do', '.action', '.groovy',
    '.gvy', '.gy', '.gsh', '.gt', '.gsp', '.r', '.rdata', '.rds',

    # Database files
    '.sql', '.sqlite', '.sqlite3', '.db', '.db3', '.mdb', '.accdb',
    '.mdf', '.ldf', '.ndf', '.dbf', '.frm', '.myd', '.myi', '.ibd',

    # Configuration files
    '.cfg', '.conf', '.config', '.ini', '.inf', '.reg', '.pol',

    # Certificate and key files
    '.crt', '.cer', '.der', '.pem', '.p12', '.pfx', '.p7b', '.p7c',
    '.key', '.keystore', '.jks', '.kdb', '.kdbx',

    # System files
    '.sys', '.dll', '.ocx', '.ax', '.cpl', '.drv', '.efi', '.acm',
    '.ax', '.bgi', '.bin', '.bpl', '.cla', '.class', '.cnt', '.com',
    '.cpl', '.csc', '.cur', '.dat', '.dbg', '.dpl', '.drv', '.ds',
    '.dsp', '.dsw', '.dxr', '.ebd', '.ecf', '.ecp', '.efi', '.enu',
    '.epf', '.erf', '.esd', '.etl', '.evt', '.evtx', '.ex_', '.exp',
    '.ext', '.fes', '.ffa', '.ffl', '.ffo', '.ffx', '.fic', '.fio',
    '.fob', '.fot', '.fp_', '.fp5', '.fp7', '.fpx', '.frm', '.frs',
    '.fth', '.fts', '.fxp', '.g2g', '.g2r', '.g2s', '.g2t', '.gadget',
    '.gcg', '.gcm', '.gcs', '.gdf', '.gdl', '.gdo', '.gem', '.gen',
    '.get', '.gfx', '.gid', '.gio', '.git', '.glb', '.glo', '.gls',
    '.glu', '.gly', '.gm6', '.gm8', '.gmk', '.gml', '.gms', '.gmz',
    '.gnc', '.gnd', '.gno', '.gnu', '.gnx', '.gof', '.gpf', '.gpk',
    '.gpn', '.gpr', '.gps', '.gpt', '.gpx', '.gqb', '.gqy', '.grf',
    '.grp', '.grx', '.gsd', '.gsh', '.gsp', '.gsr', '.gss', '.gst',
    '.gsx', '.gtd', '.gtp', '.gtr', '.gts', '.gtt', '.gtx', '.guc',
    '.gup', '.gus', '.guy', '.gv', '.gvp', '.gvr', '.gwc', '.gwd',
    '.gwi', '.gwk', '.gwm', '.gwr', '.gwt', '.gx', '.gxi', '.gxs',
    '.gxt', '.gy', '.gym', '.gzl', '.gz', '.h', '.h0', '.h1', '.h2',
    '.h3', '.h4', '.h5', '.h6', '.h7', '.h8', '.h9', '.ha', '.hap',
    '.hbe', '.hcc', '.hdp', '.hdx', '.hec', '.hep', '.hex', '.hff',
    '.hfz', '.hg', '.hge', '.hgg', '.hgl', '.hhe', '.hhk', '.hhp',
    '.hhs', '.hht', '.hif', '.hif', '.hig', '.hiv', '.hko', '.hl_',
    '.hl2', '.hl3', '.hlp', '.hme', '.hmk', '.hmp', '.hms', '.hmx',
    '.hnd', '.hni', '.hnm', '.hnt', '.hnz', '.hol', '.hop', '.hot',
    '.hp', '.hpc', '.hpd', '.hpf', '.hpg', '.hpi', '.hpj', '.hpl',
    '.hpm', '.hpp', '.hpr', '.hps', '.hpt', '.hpw', '.hqx', '.hr2',
    '.hr3', '.hr4', '.hra', '.hrc', '.hrd', '.hre', '.hrf', '.hrg',
    '.hrk', '.hrm', '.hro', '.hrp', '.hrr', '.hrs', '.hrt', '.hru',
    '.hrw', '.hrx', '.hsc', '.hsr', '.hst', '.hsv', '.ht', '.ht2',
    '.ht3', '.htc', '.htd', '.htf', '.htg', '.hti', '.htm', '.html',
    '.htn', '.htp', '.htr', '.hts', '.htt', '.htw', '.htx', '.htz',
    '.huh', '.hv_', '.hvd', '.hvp', '.hwd', '.hwp', '.hwt', '.hxc',
    '.hxd', '.hxe', '.hxl', '.hxm', '.hxn', '.hxo', '.hxp', '.hxs',
    '.hxt', '.hxx', '.hy', '.hy_', '.hyc', '.hyd', '.hyv', '.hzc',
    '.hzd', '.hzg', '.hzk', '.hzl', '.hzm', '.hzp', '.hzt', '.hzw',
]

# ============================================
# 🔴 4.2 SUSPICIOUS QUERY PARAMETERS (100+)
# ============================================

SUSPICIOUS_PARAMS = [
    # Authentication parameters
    'token', 'auth', 'authenticate', 'authorization', 'apikey', 'api_key',
    'access_token', 'refresh_token', 'id_token', 'session', 'sessionid',
    'session_id', 'sid', 'csrf', 'csrftoken', 'xsrf', 'xsrftoken',

    # User credentials
    'username', 'user', 'login', 'email', 'password', 'pass', 'pwd',
    'passwd', 'secret', 'pin', 'otp', '2fa', 'mfa', 'code', 'verification',

    # Account parameters
    'account', 'acc', 'acct', 'profile', 'userid', 'user_id', 'uid',
    'uuid', 'guid', 'member', 'memberid', 'customer', 'customerid',

    # Action parameters
    'action', 'do', 'exec', 'cmd', 'command', 'function', 'method',
    'process', 'run', 'execute', 'redirect', 'return', 'next', 'goto',
    'url', 'link', 'href', 'src', 'source', 'target', 'destination',

    # Transaction parameters
    'amount', 'money', 'price', 'cost', 'total', 'payment', 'pay',
    'checkout', 'purchase', 'buy', 'order', 'cart', 'checkout',

    # ID parameters
    'id', 'ids', 'item', 'itemid', 'product', 'productid', 'pid',
    'ref', 'reference', 'orderid', 'transaction', 'txn', 'txnid',

    # Security parameters
    'secure', 'security', 'safe', 'verify', 'validation', 'validate',
    'confirm', 'confirmation', 'approved', 'denied', 'blocked',

    # Page parameters
    'page', 'pg', 'p', 'view', 'display', 'show', 'load', 'get',
    'post', 'submit', 'form', 'input', 'field', 'fields',

    # File parameters
    'file', 'files', 'doc', 'document', 'download', 'upload', 'attach',
    'attachment', 'media', 'image', 'img', 'picture', 'photo', 'video',

    # Tracking parameters
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'fbclid', 'gclid', 'msclkid', 'ref', 'source', 'medium', 'campaign',
    'term', 'content', 'clickid', 'affid', 'affiliate', 'aff',

    # Redirect parameters
    'redirect', 'redirect_uri', 'redirect_url', 'callback', 'return_to',
    'return_url', 'next_url', 'goto', 'forward', 'destination', 'dest',
    'continue', 'cont', 'ret', 'return_path', 'return_uri',

    # State parameters
    'state', 'status', 'step', 'stage', 'phase', 'mode', 'type',
    'category', 'section', 'part', 'segment', 'channel', 'medium',

    # Debug parameters
    'debug', 'test', 'testing', 'dev', 'development', 'stage', 'staging',
    'local', 'localhost', '127.0.0.1', '0.0.0.0', '::1',

    # Administrative parameters
    'admin', 'administrator', 'root', 'super', 'superuser', 'sysadmin',
    'manage', 'management', 'control', 'panel', 'dashboard',

    # Configuration parameters
    'config', 'configuration', 'setting', 'settings', 'pref', 'prefs',
    'preference', 'preferences', 'option', 'options', 'param', 'params',

    # Language/Locale parameters
    'lang', 'language', 'locale', 'country', 'region', 'timezone',
    'tz', 'currency', 'unit', 'format',

    # Filter parameters
    'filter', 'filters', 'sort', 'order', 'sortby', 'orderby', 'group',
    'groupby', 'limit', 'offset', 'page', 'perpage', 'per_page',

    # Search parameters
    'search', 'q', 'query', 'find', 'lookup', 'keyword', 'keywords',
    'term', 'terms', 'phrase', 'text', 'string',

    # API parameters
    'api', 'apiversion', 'v', 'version', 'ver', 'format', 'callback',
    'jsonp', 'json', 'xml', 'csv', 'raw', 'pretty', 'compact',

    # Mobile parameters
    'mobile', 'app', 'android', 'ios', 'iphone', 'ipad', 'tablet',
    'phone', 'device', 'platform', 'os', 'browser', 'useragent',

    # Time parameters
    'time', 'timestamp', 'date', 'from', 'to', 'start', 'end',
    'begin', 'finish', 'duration', 'period', 'interval', 'schedule',

    # Pagination parameters
    'page', 'pages', 'pageno', 'pagenum', 'p', 'pg', 'offset', 'limit',
    'perpage', 'per_page', 'items', 'count', 'total', 'size',

    # Advanced parameters
    'async', 'sync', 'background', 'foreground', 'priority', 'queue',
    'job', 'task', 'worker', 'thread', 'process', 'fork',

    # Financial parameters
    'bank', 'account', 'routing', 'swift', 'iban', 'card', 'cvv',
    'expiry', 'expire', 'expiration', 'valid', 'validity', 'through',

    # Personal information
    'name', 'fname', 'lname', 'first', 'last', 'middle', 'fullname',
    'address', 'city', 'state', 'zip', 'postal', 'country', 'phone',
    'mobile', 'cell', 'fax', 'email', 'website', 'url', 'social',
]

# ============================================
# 🔴 8.0 RED FLAG KEYWORDS (100+)
# ============================================

RED_FLAG_KEYWORDS = [
    # Security/Account keywords
    'login', 'signin', 'sign-in', 'log-in', 'logon', 'log-on', 'signon', 'sign-on',
    'verify', 'verification', 'verify-account', 'verify-identity', 'confirm',
    'confirmation', 'validate', 'validation', 'authenticate', 'authentication',
    'authorize', 'authorization', 'secure', 'security', 'protected', 'privacy',

    # Account related
    'account', 'profile', 'myaccount', 'my-account', 'manage-account', 'settings',
    'preferences', 'dashboard', 'control-panel', 'admin', 'administrator',

    # Password related
    'password', 'passwd', 'pwd', 'passphrase', 'secret', 'pin', 'otp',
    '2fa', 'mfa', 'twofactor', 'two-factor', 'multifactor', 'multi-factor',

    # Banking/Financial
    'bank', 'banking', 'netbanking', 'online-banking', 'internet-banking',
    'credit', 'debit', 'card', 'creditcard', 'debitcard', 'cvv', 'cvv2',
    'atm', 'pin', 'wallet', 'digital-wallet', 'payment', 'payments',
    'transaction', 'transfer', 'withdraw', 'deposit', 'balance', 'statement',
    'invoice', 'bill', 'receipt', 'payment-due', 'overdue', 'collection',

    # PayPal specific
    'paypal', 'pay-pal', 'paypall', 'paypal.com', 'paypal.me', 'paypal-',
    'paypal-login', 'paypal-secure', 'paypal-verify', 'paypal-confirm',
    'paypal-account', 'paypal-payment', 'paypal-billing', 'paypal-invoice',

    # Amazon specific
    'amazon', 'amazon.com', 'amazon-', 'amazon-login', 'amazon-secure',
    'amazon-verify', 'amazon-confirm', 'amazon-account', 'amazon-payment',
    'amazon-order', 'amazon-prime', 'amazon-gift', 'amazon-wallet',

    # Apple specific
    'apple', 'apple.com', 'apple-id', 'appleid', 'icloud', 'apple-icloud',
    'apple-login', 'apple-secure', 'apple-verify', 'apple-pay', 'app-store',
    'itunes', 'itunes-store', 'apple-music', 'apple-tv', 'apple-card',

    # Microsoft specific
    'microsoft', 'outlook', 'hotmail', 'live.com', 'msn.com', 'microsoft-',
    'windows', 'office365', 'microsoft-account', 'microsoft-login',
    'microsoft-secure', 'microsoft-verify', 'microsoft-teams', 'skype',
    'onedrive', 'sharepoint', 'xbox', 'xbox-live', 'xbox-gold',

    # Google specific
    'google', 'gmail', 'google-account', 'google-login', 'google-secure',
    'google-verify', 'google-authenticator', 'google-authentication',
    'google-wallet', 'google-pay', 'google-play', 'google-drive',
    'google-photos', 'google-docs', 'google-sheets', 'google-slides',
    'youtube', 'youtube-account', 'youtube-login', 'youtube-premium',

    # Social Media
    'facebook', 'fb', 'instagram', 'ig', 'whatsapp', 'wa', 'twitter', 'x',
    'linkedin', 'snapchat', 'tiktok', 'pinterest', 'reddit', 'discord',
    'telegram', 'signal', 'wechat', 'line', 'viber', 'skype', 'teams',
    'zoom', 'meet', 'hangouts', 'messenger', 'whatsapp-web', 'instagram-',
    'facebook-', 'twitter-', 'linkedin-', 'snapchat-', 'tiktok-',

    # E-commerce
    'shop', 'store', 'cart', 'checkout', 'purchase', 'buy', 'order',
    'shipping', 'billing', 'delivery', 'track', 'tracking', 'return',
    'refund', 'cancel', 'subscription', 'renew', 'upgrade', 'downgrade',

    # Urgency/Scare tactics
    'urgent', 'immediate', 'attention', 'important', 'alert', 'warning',
    'suspended', 'blocked', 'restricted', 'limited', 'expiring', 'expires',
    'deadline', 'final', 'last-chance', 'act-now', 'donotmiss', 'hurry',
    'expired', 'suspended', 'deactivated', 'disabled', 'locked', 'frozen',

    # Offers/Incentives
    'free', 'bonus', 'prize', 'winner', 'win', 'won', 'gift', 'reward',
    'cashback', 'discount', 'offer', 'special', 'exclusive', 'limited-time',
    'limited-offer', 'special-offer', 'exclusive-offer', 'one-time',

    # Personal information
    'personal', 'private', 'confidential', 'sensitive', 'secret', 'hidden',
    'update-info', 'update-profile', 'update-account', 'update-payment',
    'update-billing', 'update-shipping', 'update-details', 'verify-info',
    'confirm-info', 'validate-info', 'verify-identity', 'confirm-identity',

    # File/Download
    'download', 'upload', 'file', 'files', 'doc', 'docs', 'document',
    'pdf', 'exe', 'zip', 'rar', 'software', 'installer', 'setup',
    'update', 'upgrade', 'patch', 'fix', 'hotfix', 'service-pack',

    # Tech support scams
    'support', 'help', 'helpdesk', 'tech-support', 'customer-support',
    'customer-service', 'service', 'assistance', 'live-chat', 'chat',
    'remote-support', 'remote-access', 'remote-control', 'tech-support',
    'microsoft-support', 'apple-support', 'google-support', 'amazon-support',

    # COVID-19 related
    'covid', 'covid19', 'covid-19', 'corona', 'coronavirus', 'pandemic',
    'vaccine', 'vaccination', 'vaccine-registration', 'covid-test',
    'covid-relief', 'covid-aid', 'covid-help', 'covid-support',

    # Government related
    'gov', 'government', 'irs', 'tax', 'taxes', 'tax-return', 'tax-refund',
    'social-security', 'ssn', 'itin', 'passport', 'visa', 'immigration',
    'uscis', 'dhs', 'fbi', 'cia', 'nsa', 'dod', 'veteran', 'va',
    'medicare', 'medicaid', 'healthcare', 'healthcare-gov', 'obamacare',

    # Indian specific
    'aadhaar', 'aadhar', 'pan', 'pan-card', 'voter-id', 'driving-license',
    'passport-india', 'visa-india', 'epfo', 'esic', 'gst', 'gstin',
    'income-tax', 'incometax', 'itr-filing', 'tds', 'tds-return',
    'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'pnb', 'canara', 'unionbank',
    'upi', 'bhimpay', 'phonepe', 'googlepay', 'paytm', 'amazonpay',

    # Cryptocurrency
    'bitcoin', 'btc', 'ethereum', 'eth', 'crypto', 'cryptocurrency',
    'wallet', 'blockchain', 'mining', 'investment', 'invest', 'trading',
    'exchange', 'coinbase', 'binance', 'kraken', 'ftx', 'crypto.com',
    'metamask', 'trustwallet', 'ledger', 'trezor', 'cold-wallet',

    # Romance scams
    'dating', 'love', 'match', 'single', 'meet', 'date', 'romance',
    'relationship', 'partner', 'soulmate', 'true-love', 'find-love',
    'dating-site', 'dating-app', 'dating-service', 'online-dating',

    # Job scams
    'job', 'jobs', 'career', 'careers', 'employment', 'recruitment',
    'hiring', 'work-from-home', 'remote-work', 'remote-job', 'freelance',
    'gig', 'side-hustle', 'extra-income', 'passive-income', 'earn-money',
    'make-money', 'get-rich', 'quick-money', 'easy-money', 'work-online',

    # Investment scams
    'investment', 'invest', 'trading', 'forex', 'stocks', 'options',
    'futures', 'commodities', 'real-estate', 'property', 'land',
    'gold', 'silver', 'platinum', 'palladium', 'rare-earth',
    'cryptocurrency', 'bitcoin', 'ethereum', 'altcoin', 'ico',

    # Lottery/Contest scams
    'lottery', 'lotto', 'raffle', 'sweepstakes', 'contest', 'competition',
    'giveaway', 'freebie', 'prize', 'reward', 'bonus', 'cash', 'money',
    'million', 'billion', 'fortune', 'wealth', 'rich', 'luxury',

    # Charity scams
    'charity', 'donation', 'donate', 'fundraiser', 'fundraising',
    'nonprofit', 'ngo', 'foundation', 'cause', 'help', 'relief',
    'aid', 'assistance', 'support', 'sponsor', 'sponsorship',
]


# ============================================
# HELPER FUNCTIONS
# ============================================

def normalize_url(u):
    """Normalize URL for consistent processing"""
    if not u or not isinstance(u, str):
        return ""
    u = u.strip().lower()
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    return u


def shannon_entropy(s):
    """Calculate Shannon entropy of a string"""
    s = safe_str(s)
    if not s or len(s) == 0:
        return 0
    entropy = 0
    for i in range(256):
        char = chr(i)
        freq = s.count(char)
        if freq > 0:
            freq = float(freq) / len(s)
            entropy -= freq * math.log2(freq)
    return entropy


def is_ip_address(domain):
    """Check if domain is an IP address"""
    if not domain:
        return 0
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, domain):
        parts = domain.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            return 1
    return 0


def count_digits(text):
    """Count digits in text"""
    return sum(c.isdigit() for c in safe_str(text))


def count_special_chars(text):
    """Count special characters"""
    text = safe_str(text)
    special = '!@#$%^&*()_+-=[]{}|;:,.<>?/~`'
    return sum(1 for c in text if c in special)


def is_uuid(text):
    """Check if text is a UUID pattern"""
    uuid_pattern = r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
    return bool(re.match(uuid_pattern, text.lower()))


def is_legitimate_subdomain(domain, main_domain):
    """
    Check if this is a legitimate subdomain of a known brand
    Example: chat.deepseek.com is legitimate if deepseek is in COMMON_BRANDS
    """
    for brand in COMMON_BRANDS:
        brand_lower = brand.lower()
        if main_domain == brand_lower:
            return True
    return False


def check_typosquatting(domain, main_domain):
    """
    🔴 1.1 DYNAMIC TYPOSQUATTING DETECTION
    Uses COMMON_TYPOS dictionary and intelligent matching
    """
    main_domain_lower = main_domain.lower()

    # ✅ LEGITIMATE SITE CHECK: If main domain exactly matches a brand, it's NOT typosquatting
    for brand in COMMON_BRANDS:
        brand_lower = brand.lower()
        if main_domain_lower == brand_lower:
            return 0, None  # Exact match = legitimate

    # ✅ LEGITIMATE SUBDOMAIN CHECK: e.g., chat.deepseek.com
    if is_legitimate_subdomain(domain, main_domain):
        return 0, None

    # Check against COMMON_TYPOS dictionary
    for brand, typos in COMMON_TYPOS.items():
        # Check if main domain is in the typos list
        if main_domain_lower in typos:
            return 1, brand

        # Check if main domain is similar to any typo
        for typo in typos:
            # Remove spaces for comparison
            typo_clean = typo.replace(' ', '')
            main_clean = main_domain_lower.replace(' ', '')

            if typo_clean == main_clean:
                return 1, brand

            # Check Levenshtein distance for close matches
            if abs(len(main_clean) - len(typo_clean)) <= 2:
                distance = Levenshtein.distance(main_clean, typo_clean)
                if distance <= 2:
                    return 1, brand

    # Check number/letter substitutions
    for brand in COMMON_BRANDS:
        brand_lower = brand.lower()
        if len(brand_lower) < 3:
            continue

        # Check for common substitutions
        for original, substitutions in CHAR_SUBSTITUTIONS.items():
            for sub in substitutions:
                if sub in main_domain_lower:
                    # Try replacing the substitution
                    test_domain = main_domain_lower.replace(sub, original)
                    if brand_lower == test_domain or brand_lower in test_domain:
                        return 1, brand

    return 0, None


def check_brand_in_subdomain(domain, main_domain):
    """
    🔴 1.3 BRAND IN SUBDOMAIN DETECTION
    Example: paypal.login.secure.com (paypal is in subdomain)
    """
    domain_lower = domain.lower()
    main_domain_lower = main_domain.lower()

    # Don't flag if it's a legitimate subdomain
    if is_legitimate_subdomain(domain, main_domain):
        return 0, None

    for brand in COMMON_BRANDS:
        brand_lower = brand.lower()
        if len(brand_lower) < 3:
            continue

        # Brand in domain but not in main domain
        if brand_lower in domain_lower and brand_lower not in main_domain_lower:
            return 1, brand

    return 0, None


def count_subdomains(domain):
    """Count subdomains"""
    parts = domain.split('.')
    if len(parts) > 2:
        return len(parts) - 2
    return 0


def check_suspicious_tld(tld):
    """Check if TLD is suspicious"""
    return 1 if tld in SUSPICIOUS_TLDS else 0


def check_safe_tld(tld):
    """Check if TLD is safe"""
    return 1 if tld in SAFE_TLDS else 0


def is_url_shortener(domain):
    """Check if domain is a URL shortener"""
    for shortener in URL_SHORTENERS:
        if shortener in domain:
            return 1
    return 0


def extract_path_features(path):
    """
    🔴 3. PATH FEATURES with UUID detection
    """
    features = {}

    # Path length
    features['path_length'] = len(path)

    # Count path segments
    path_segments = [seg for seg in path.split('/') if seg]
    features['token_count'] = len(path_segments)

    # Check for UUIDs in path (legitimate)
    uuid_count = 0
    for segment in path_segments:
        if is_uuid(segment):
            uuid_count += 1

    features['uuid_in_path'] = uuid_count

    # Check for suspicious file extensions (only at the END of path)
    features['suspicious_file_extension'] = 0

    if path_segments:
        last_segment = path_segments[-1].lower()

        # Check if it looks like a filename with extension and NOT a UUID
        if '.' in last_segment and not is_uuid(last_segment):
            parts = last_segment.split('.')
            if len(parts) > 1:
                ext = '.' + parts[-1]
                # Check against suspicious extensions
                if ext in SUSPICIOUS_EXTENSIONS:
                    features['suspicious_file_extension'] = 1

    # Check for double slash redirects
    features['double_slash_redirect'] = 1 if '//' in path and path.index('//') > 0 else 0

    return features


def extract_query_features(query):
    """Extract query parameter features"""
    features = {}

    # Count query parameters
    params = parse_qs(query)
    features['query_param_count'] = len(params)

    # Check for suspicious parameters
    features['suspicious_param_count'] = 0
    param_names = [p.lower() for p in params.keys()]

    for param in param_names:
        if param in SUSPICIOUS_PARAMS:
            features['suspicious_param_count'] += 1

    return features


def count_red_flag_keywords(url):
    """Count red flag keywords in URL"""
    url_lower = url.lower()
    count = 0

    for keyword in RED_FLAG_KEYWORDS:
        if keyword in url_lower:
            count += 1

    return count


def calculate_url_entropy(url):
    """Calculate URL entropy, adjusting for UUIDs"""
    base_entropy = shannon_entropy(url)

    # If URL contains UUIDs, reduce entropy score (UUIDs are legitimate)
    if re.search(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', url.lower()):
        base_entropy = max(2.5, base_entropy - 1.0)

    return base_entropy


def extract_static_features(url):
    """
    Main function to extract ALL static features
    """
    features = {}

    try:
        # Normalize URL
        url = normalize_url(url)
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query
        full_url = url.lower()

        # Extract domain parts
        extracted = tldextract.extract(url)
        main_domain = extracted.domain
        tld = extracted.suffix
        subdomain = extracted.subdomain

        # Check if this is a legitimate subdomain
        legitimate = is_legitimate_subdomain(domain, main_domain)

        # ===== 1. DOMAIN-BASED FEATURES =====

        # 1.1 Typosquatting detection
        if legitimate:
            features['typosquatting'] = 0
        else:
            typosquatting, brand = check_typosquatting(domain, main_domain)
            features['typosquatting'] = typosquatting

        # 1.2 Suspicious TLD
        features['tld_popularity'] = 0 if check_suspicious_tld(tld) else 1
        features['tld_length'] = len(tld)

        # 1.3 Subdomain count
        features['subdomain_count'] = count_subdomains(domain)

        # 1.4 IP address
        features['has_ip_address'] = is_ip_address(domain.split(':')[0])

        # 1.5 Domain name length
        features['domain_name_length'] = len(main_domain)

        # 1.6 Digit count in domain
        features['number_of_digits_domain'] = count_digits(main_domain)

        # 1.7 Hyphen in domain
        features['has_hyphen_in_domain'] = 1 if '-' in main_domain else 0

        # 1.8 Domain entropy
        features['domain_entropy'] = round(shannon_entropy(domain), 2)

        # 1.9 URL shortener
        features['is_shortened'] = is_url_shortener(domain)

        # Brand in subdomain (only if not legitimate)
        if legitimate:
            features['brand_in_subdomain'] = 0
        else:
            brand_in_subdomain, _ = check_brand_in_subdomain(domain, main_domain)
            features['brand_in_subdomain'] = brand_in_subdomain

        # ===== 2. URL STRUCTURE FEATURES =====
        features['url_length'] = len(full_url)
        features['dot_count'] = domain.count('.')
        features['special_char_count'] = count_special_chars(full_url)
        features['number_of_digits'] = count_digits(full_url)
        features['has_at_symbol'] = 1 if '@' in full_url else 0
        features['https_flag'] = 1 if parsed.scheme == 'https' else 0

        if len(full_url) > 0:
            features['percentage_numeric_chars'] = round((count_digits(full_url) / len(full_url)) * 100, 2)
        else:
            features['percentage_numeric_chars'] = 0

        # ===== 3. PATH FEATURES =====
        path_features = extract_path_features(path)
        features.update(path_features)

        # ===== 4. QUERY FEATURES =====
        query_features = extract_query_features(query)
        features.update(query_features)

        # ===== 5. ENTROPY FEATURES =====
        features['url_entropy'] = round(calculate_url_entropy(full_url), 2)
        features['path_entropy'] = round(shannon_entropy(path), 2)
        features['query_entropy'] = round(shannon_entropy(query), 2)

        # ===== 6. RED FLAG KEYWORDS =====
        features['red_flag_keyword_count'] = count_red_flag_keywords(full_url)

        # ===== 7. UUID DETECTION =====
        features['has_uuid'] = 1 if features.get('uuid_in_path', 0) > 0 else 0

        # ===== 8. ADDITIONAL FEATURES =====
        # Check for double slash in path
        features['double_slash_in_path'] = 1 if '//' in path and '://' not in path else 0

        # Check for multiple encodings
        features['has_percent_encoding'] = 1 if '%' in full_url else 0

        # Count total special characters
        features['total_special_chars'] = features['special_char_count']

    except Exception as e:
        print(f"Error extracting features: {e}")
        # Default values
        features = {
            'typosquatting': 0, 'tld_popularity': 0, 'tld_length': 0,
            'subdomain_count': 0, 'has_ip_address': 0, 'domain_name_length': 0,
            'number_of_digits_domain': 0, 'has_hyphen_in_domain': 0,
            'domain_entropy': 0, 'brand_in_subdomain': 0, 'is_shortened': 0,
            'url_length': 0, 'dot_count': 0, 'special_char_count': 0,
            'number_of_digits': 0, 'has_at_symbol': 0, 'percentage_numeric_chars': 0,
            'https_flag': 0, 'path_length': 0, 'token_count': 0,
            'suspicious_file_extension': 0, 'double_slash_redirect': 0,
            'query_param_count': 0, 'suspicious_param_count': 0,
            'url_entropy': 0, 'red_flag_keyword_count': 0,
            'path_entropy': 0, 'query_entropy': 0,
            'double_slash_in_path': 0, 'has_percent_encoding': 0,
            'total_special_chars': 0, 'uuid_in_path': 0, 'has_uuid': 0
        }

    return features