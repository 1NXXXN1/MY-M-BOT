# https://github.com/Appeza/tg-mirror-leech-bot edited by HuzunluArtemis

from psutil import disk_usage, cpu_percent, swap_memory, cpu_count, virtual_memory, net_io_counters
from bot.helper.ext_utils.bot_utils import get_readable_file_size, get_readable_time
from time import time
from subprocess import run
import requests
from bot import LOGGER, dispatcher, botStartTime, HEROKU_API_KEY, HEROKU_APP_NAME
from telegram.ext import CommandHandler
from bot.helper.telegram_helper.message_utils import sendMessage
from bot.helper.telegram_helper.filters import CustomFilters
from bot.helper.telegram_helper.bot_commands import BotCommands
from bot.modules.wayback import getRandomUserAgent


def getHerokuDetails(h_api_key, h_app_name):
    try: import heroku3
    except ModuleNotFoundError: run("pip install heroku3", capture_output=False, shell=True)
    try: import heroku3
    except Exception as f:
        LOGGER.warning("heroku3 cannot imported. add to your deployer requirements.txt file.")
        LOGGER.warning(f)
        return None
    if (not h_api_key) or (not h_app_name): return None
    try:
        heroku_api = "https://api.heroku.com"
        Heroku = heroku3.from_key(h_api_key)
        app = Heroku.app(h_app_name)
        useragent = getRandomUserAgent()
        user_id = Heroku.account().id
        headers = {
            "User-Agent": useragent,
            "Authorization": f"Bearer {h_api_key}",
            "Accept": "application/vnd.heroku+json; version=3.account-quotas",
        }
        path = "/accounts/" + user_id + "/actions/get-quota"
        session = requests.Session()
        result = (session.get(heroku_api + path, headers=headers)).json()
        abc = ""
        account_quota = result["account_quota"]
        quota_used = result["quota_used"]
        quota_remain = account_quota - quota_used
        abc += f"Full: {get_readable_time(account_quota)} | "
        abc += f"Used: {get_readable_time(quota_used)} | "
        abc += f"Free: {get_readable_time(quota_remain)}\n"
        # App Quota
        AppQuotaUsed = 0
        OtherAppsUsage = 0
        for apps in result["apps"]:
            if str(apps.get("app_uuid")) == str(app.id):
                try:
                    AppQuotaUsed = apps.get("quota_used")
                except Exception as t:
                    LOGGER.error("error when adding main dyno")
                    LOGGER.error(t)
                    pass
            else:
                try:
                    OtherAppsUsage += int(apps.get("quota_used"))
                except Exception as t:
                    LOGGER.error("error when adding other dyno")
                    LOGGER.error(t)
                    pass
        LOGGER.info(f"This App: {str(app.name)}")
        abc += f"App Usage: {get_readable_time(AppQuotaUsed)}"
        abc += f" | Other Apps: {get_readable_time(OtherAppsUsage)}"
        return abc
    except Exception as g:
        LOGGER.error(g)
        return None

def stats(update, context):
    currentTime = get_readable_time(time() - botStartTime)
    total, used, free, disk= disk_usage('/')
    total = get_readable_file_size(total)
    used = get_readable_file_size(used)
    free = get_readable_file_size(free)
    sent = get_readable_file_size(net_io_counters().bytes_sent)
    recv = get_readable_file_size(net_io_counters().bytes_recv)
    cpuUsage = cpu_percent(interval=0.5)
    p_core = cpu_count(logical=False)
    t_core = cpu_count(logical=True)
    swap = swap_memory()
    swap_p = swap.percent
    swap_t = get_readable_file_size(swap.total)
    swap_u = get_readable_file_size(swap.used)
    swap_f = get_readable_file_size(swap.free)
    memory = virtual_memory()
    mem_p = memory.percent
    mem_t = get_readable_file_size(memory.total)
    mem_a = get_readable_file_size(memory.available)
    mem_u = get_readable_file_size(memory.used)
    stats = f'<b>Disk:</b> {total} | <b>Used:</b> {used} | <b>Free:</b> {free}\n' \
            f'<b>SWAP:</b> {swap_t} | <b>Used:</b> {swap_u}% | <b>Free:</b> {swap_f}\n\n'\
            f'<b>Memory:</b> {mem_t} | <b>Used:</b> {mem_u} | <b>Free:</b> {mem_a}\n' \
            f'<b>Cores:</b> {t_core} | <b>Physical:</b> {p_core} | <b>Logical:</b> {t_core - p_core} | <b>Uptime:</b> {currentTime}\n\n' \
            f'<b>DISK:</b> {disk}% | <b>RAM:</b> {mem_p}% | <b>CPU:</b> {cpuUsage}% | <b>SWAP:</b> {swap_p}%\n' \
            f'<b>Total Upload:</b> {sent} | <b>Total Download:</b> {recv}\n\n'
    heroku = getHerokuDetails(HEROKU_API_KEY, HEROKU_APP_NAME)
    if heroku: stats += heroku
    sendMessage(stats, context.bot, update)

stats_handler = CommandHandler(BotCommands.StatsCommand, stats,
    filters=CustomFilters.authorized_chat | CustomFilters.authorized_user, run_async=True)
dispatcher.add_handler(stats_handler)
