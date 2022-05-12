from bot.helper.ext_utils.shortenurl import short_url
from telegram.ext import CommandHandler
import re
from bot.helper.telegram_helper.filters import CustomFilters
from bot import dispatcher
from bot.helper.telegram_helper.bot_commands import BotCommands
from bot.helper.telegram_helper.message_utils import sendMessage

def getListAsString(liste, splitter = ","):
    toret = ""
    for i, item in enumerate(liste):
        toret += f"<code>{item}</code>"
        if i != len(liste)-1: toret += f"{splitter} "
    return toret


def shortener(update, context):
    message = update.effective_message
    link = None
    domain = None
    if message.reply_to_message: link = message.reply_to_message.text
    else:
        link = message.text.split(' ')
        if len(link) < 2 or len(link) > 3:
            apireq = ["shorte.st", "bc.vc", "pubiza", "linkvertise", "bit.ly", "post", "cutt.ly", "adf.ly", "shortcm", "tinycc", "ouo.io"]
            free = ["v.gd", "da.gd", "is.gd", "ttm.sh", "clck.ru", "chilp.it", "osdb", "owly", "tinyurl"]
            apireq = getListAsString(apireq)
            free = getListAsString(free)
            help_msg = "<b>Send link after command:</b>"
            help_msg += f"\n<code>/{BotCommands.ShortenerCommand}" + " {link}" + "</code>"
            help_msg += "\n<b>Select shortener:</b>"
            help_msg += f"\n<code>/{BotCommands.ShortenerCommand} is.gd " + " {link}" + "</code>"
            help_msg += "\n<b>By replying to message (including link):</b>"
            help_msg += f"\n<code>/{BotCommands.ShortenerCommand}" + " {message}" + "</code>"
            help_msg += "\nAll supported domains: " + free 
            help_msg += "\nRequires APIKEY: " + apireq
            return sendMessage(help_msg, context.bot, update)
        if len(link) == 2:
            link = link[1]
        if len(link) == 3:
            domain = link[1]
            link = link[2]
    try: link = re.match(r"((http|https)\:\/\/)?[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z]){2,6}([a-zA-Z0-9\.\&\/\?\:@\-_=#])*", link)[0]
    except TypeError: return sendMessage('Not a valid link.', context.bot, update)
    return sendMessage(short_url(link, domain), context.bot, update)


shortener_handler = CommandHandler(BotCommands.ShortenerCommand, shortener,
    CustomFilters.authorized_chat | CustomFilters.authorized_user, run_async=True)

dispatcher.add_handler(shortener_handler)
