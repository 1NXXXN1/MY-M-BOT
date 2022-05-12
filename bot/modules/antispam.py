# written by huzunluartemis

from bot import COMBOT_CAS_ANTISPAM, INTELLIVOID_ANTISPAM, LOGGER, SPAMWATCH_ANTISPAM_API, USERGE_ANTISPAM_API, dispatcher, app
from telegram.ext import ChatMemberHandler, CallbackContext
from telegram import Update
import requests
from telegram.update import Update
from telegram.error import RetryAfter
from time import sleep
from typing import Tuple, Optional
from telegram import Update, Chat, ChatMember, ChatMemberUpdated
from telegram.ext import CallbackContext, ChatMemberHandler



def extract_status_change(
    chat_member_update: ChatMemberUpdated,
) -> Optional[Tuple[bool, bool]]:
    """Takes a ChatMemberUpdated instance and extracts whether the 'old_chat_member' was a member
    of the chat and whether the 'new_chat_member' is a member of the chat. Returns None, if
    the status didn't change.
    """
    status_change = chat_member_update.difference().get("status")
    old_is_member, new_is_member = chat_member_update.difference().get("is_member", (None, None))

    if status_change is None:
        return None

    old_status, new_status = status_change
    was_member = (
        old_status
        in [
            ChatMember.MEMBER,
            ChatMember.CREATOR,
            ChatMember.ADMINISTRATOR,
        ]
        or (old_status == ChatMember.RESTRICTED and old_is_member is True)
    )
    is_member = (
        new_status
        in [
            ChatMember.MEMBER,
            ChatMember.CREATOR,
            ChatMember.ADMINISTRATOR,
        ]
        or (new_status == ChatMember.RESTRICTED and new_is_member is True)
    )

    return was_member, is_member


def SpamWatchAntiSpamCheck(userid):
    if not SPAMWATCH_ANTISPAM_API: return None
    userid = str(userid)
    api = 'https://api.spamwat.ch'
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {SPAMWATCH_ANTISPAM_API}"})
    req = session.request('get', f'{api}/banlist/{userid}')
    if not req.status_code == 200: return None
    info = "#Spamwatch Ban Info:"
    try:
        admin = req.json()['admin']
        id = req.json()['id']
        reason = req.json()['reason']
        message = req.json()['message']
        date = req.json()['date']
        if admin: info += f"\nAdmin: {admin}"
        if id: info += f"\nID: {id}"
        if reason: info += f"\nReason: {reason}"
        if message: info += f"\nMessage: {message}"
        if date: info += f"\nDate: {date}"
        LOGGER.info(info)
        return info
    except Exception as e:
        LOGGER.error(e)
        return None


def CombotAntiSpamCheck(userid):
    if not COMBOT_CAS_ANTISPAM: return None
    userid = str(userid)
    api = f"https://api.cas.chat/check?user_id={userid}"
    session = requests.Session()
    req = session.request('get', api)
    if not int(req.status_code) == 200: return None
    if not bool(req.json()['ok']): return None
    info = "#Combot Ban Info:"
    result = req.json()['result']
    if not result: return info
    try:
        offenses = result['offenses']
        time_added = result['time_added']
        info += f"\nOffenses: {offenses}"
        info += f"\nTime: {time_added}"
        info += f"\nLink: <a href='https://cas.chat/query?u={userid}'>CAS Report</a>"
        info += f"\nCopy: <code>https://cas.chat/query?u={userid}</code>"
        LOGGER.info(info)
        return info
    except Exception as e:
        LOGGER.error(e)
        return None


def UsergeAntiSpamCheck(userid):
    if not USERGE_ANTISPAM_API: return None
    userid = str(userid)
    api = f"https://api.userge.tk/ban?api_key={USERGE_ANTISPAM_API}&user_id={userid}"
    session = requests.Session()
    req = session.request('get', api)
    if not bool(req.json()['success']): return None
    info = "#Userge Ban Info:"
    try:
        reason = req.json()['reason']
        date = req.json()['date']
        bb_user_id = req.json()['banned_by']['user_id']
        bb_user_name = req.json()['banned_by']['name']
        if reason: info += f"\nReason: {reason}"
        if date: info += f"\nDate: {date}"
        if bb_user_name: info += f"\nBanned by: {bb_user_name}"
        if bb_user_id: info += f" <a href='tg://user?id={bb_user_id}'>({str(bb_user_id)})</a>"
        LOGGER.info(info)
        return info
    except Exception as e:
        LOGGER.error(e)
        return None


def IntelliVoidSpamCheck(userid):
    if not INTELLIVOID_ANTISPAM: return None
    userid = str(userid)
    api = f"https://api.intellivoid.net/spamprotection/v1/lookup?query={userid}"
    session = requests.Session()
    req = session.request('get', api)
    if not bool(req.json()['success']): return None
    info = "#IntelliVoid Ban Info:"
    # print(json.dumps(json.loads(req.text), indent=4, sort_keys=True))
    try:
        is_potential_spammer = req.json()['results']['attributes']['is_potential_spammer']
        is_blacklisted = req.json()['results']['attributes']['is_blacklisted']
        language = req.json()['results']['language_prediction']['language']
        probability = req.json()['results']['language_prediction']['probability']
        spam_prediction = req.json()['results']['spam_prediction']['spam_prediction']
        ham_prediction = req.json()['results']['spam_prediction']['ham_prediction']
        last_updated = req.json()['results']['last_updated']
        info += f"\nPotential Spammer: {str(is_potential_spammer)}"
        info += f"\nBlacklisted: {str(is_blacklisted)}"
        if language: info += f"\nLanguage: {language}"
        if probability: info += f"\nProbability: {probability}"
        if spam_prediction: info += f"\nSpam Prediction: {spam_prediction}"
        if ham_prediction: info += f"\nHam Prediction: {ham_prediction}"
        if last_updated: info += f"\nLast Updated: {last_updated}"
        if language: info += f"\nLanguage: {language}"
        LOGGER.info(info)
        if bool(is_potential_spammer) or bool(is_blacklisted): return info
        else: return None
    except Exception as e:
        LOGGER.error(e)
        return None


def send_message(text: str, context, groupid):
    try:
        return context.bot.send_message(groupid.id, text, parse_mode='html', disable_web_page_preview=True)
    except RetryAfter as r:
        LOGGER.warning(str(r))
        sleep(r.retry_after * 1.5)
        return send_message(text, context, groupid)
    except Exception as e:
        LOGGER.error(str(e))
        return


def antispam(update: Update, context: CallbackContext) -> None:
    if (not SPAMWATCH_ANTISPAM_API) and (not COMBOT_CAS_ANTISPAM) and (not USERGE_ANTISPAM_API): return
    group = update.effective_chat
    a = context.bot.get_chat_member(group.id, context.bot.id).can_restrict_members
    if not a: return LOGGER.warning("Give ban permission to bot for spam api.")
    chat = update.effective_chat
    if not chat.type in [Chat.GROUP, Chat.SUPERGROUP]: return # only work for groups
    result = extract_status_change(update.chat_member)
    if result is None: return
    was_member, is_member = result
    if not is_member: return # user leaved
    cause_name = update.chat_member.from_user.mention_html()
    member_name = update.chat_member.new_chat_member.user.mention_html()
    banned = None
    if SPAMWATCH_ANTISPAM_API: banned = SpamWatchAntiSpamCheck(update.chat_member.new_chat_member.user.id)
    if not banned:
        if COMBOT_CAS_ANTISPAM: banned = CombotAntiSpamCheck(update.chat_member.new_chat_member.user.id)
    if not banned:
        if USERGE_ANTISPAM_API: banned = UsergeAntiSpamCheck(update.chat_member.new_chat_member.user.id)
    if not banned:
        if INTELLIVOID_ANTISPAM: banned = IntelliVoidSpamCheck(update.chat_member.new_chat_member.user.id)
    if not banned: return LOGGER.info(f"User is clean: {str(update.chat_member.new_chat_member.user.full_name)}")
    else:
        try:
            app.ban_chat_member(group.id, update.chat_member.new_chat_member.user.id)
            success = "Success"
        except Exception as o:
            success = "Unsuccess"
            LOGGER.error(o)
        swtc = f"{cause_name} Added: {member_name}"
        swtc += f"\nID: <code>{str(update.chat_member.new_chat_member.user.id)}</code>"
        swtc += f"\nBan: {success}"
        swtc += f"\n{banned}"
        send_message(swtc, context, group)

if SPAMWATCH_ANTISPAM_API or COMBOT_CAS_ANTISPAM or USERGE_ANTISPAM_API or INTELLIVOID_ANTISPAM:
    antispam_handler = ChatMemberHandler(antispam, ChatMemberHandler.CHAT_MEMBER, run_async=True)
    dispatcher.add_handler(antispam_handler)
else: LOGGER.info('No using any Spam Protection.')
