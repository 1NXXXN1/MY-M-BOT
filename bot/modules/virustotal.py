import subprocess
from telegram import Message
import re, hashlib, requests, os
from bot.helper.ext_utils.shortenurl import short_url
from telegram.ext import CommandHandler
from bot import LOGGER, VIRUSTOTAL_API, VIRUSTOTAL_FREE, dispatcher, app
from bot.helper.telegram_helper.filters import CustomFilters
from bot.helper.telegram_helper.bot_commands import BotCommands
from bot.helper.telegram_helper.message_utils import editMessage, sendMessage

baseUrlFile = 'https://www.virustotal.com/vtapi/v2/file/'
baseUrlUrl = 'https://www.virustotal.com/vtapi/v2/url/'
apiKey = VIRUSTOTAL_API

def get_report(file_hash, link = False):
    '''
    :param file_hash: md5/sha1/sha256
    :return: json response / None
    '''
    try:
        LOGGER.info("VirusTotal - Check for existing report")
        url = ""
        if link: url = baseUrlUrl + 'report'
        else: url = baseUrlFile + 'report'
        params = {
            'apikey': apiKey,
            'resource': file_hash
        }
        headers = {"Accept-Encoding": "gzip, deflate"}
        try:
            response = requests.get(url, params=params, headers=headers)
            if response.status_code == 403:
                LOGGER.error("VirusTotal -  Permission denied, wrong api key?")
                return None
        except:
            LOGGER.error("VirusTotal -  ConnectionError, check internet connectivity")
            return None
        try:
            return response.json()
        except ValueError:
            return None
    except Exception as e:
        LOGGER.error(e)
        return None

def upload_file(file_path, islink = False):
    '''
    :param file_path: file path to upload
    :return: json response / None
    '''
    try:
        url = ""
        if islink: url = baseUrlUrl + 'scan'
        else: url = baseUrlFile + 'scan'
        if islink:
            params = {
                'apikey': apiKey,
                'url': file_path
            }
            response = requests.post(url, data=params)
        else:
            if os.path.getsize(file_path) > 32*1024*1024:
                url = 'https://www.virustotal.com/vtapi/v2/file/scan/upload_url'
                params = {'apikey': apiKey}
                response = requests.get(url, params=params)
                upload_url_json = response.json()
                url = upload_url_json['upload_url']
            files = {'file': open(file_path, 'rb')}
            headers = {"apikey": apiKey}
            response = requests.post(url, files=files, data=headers)
        if not response:
            LOGGER.error("VirusTotal -  ConnectionError, check internet connectivity")
            return None
        if response.status_code == 403:
            LOGGER.error("VirusTotal -  Permission denied, wrong api key?")
            return None
        json_response = response.json()
        return json_response
    except:
        LOGGER.error("VirusTotal -  upload_file")
        return None


def getMD5(path):
    f = open(path, "rb")
    file_hash = hashlib.md5()
    chunk = f.read(8192)
    while chunk:
        file_hash.update(chunk)
        chunk = f.read(8192)
    f.close()
    return file_hash.hexdigest()


def get_result(file_path):
    '''
    Uoloading a file and getting the approval msg from VT or fetching existing report
    :param file_path: file's path
    :param file_hash: file's hash - md5/sha1/sha256
    :return: VirusTotal result json / None upon error
    '''
    hash = None
    file = False
    url = False
    # file
    try:
        file = True if os.path.isfile(file_path) else False
        LOGGER.info("file was True")
    except Exception as e:
        LOGGER.error(e)
        file = False
    # url
    if not file:
        try:
            hash = re.match(r"((http|https)\:\/\/)?[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z]){2,6}([a-zA-Z0-9\.\&\/\?\:@\-_=#])*", file_path)[0]
            url = True
            LOGGER.info("url was True")
        except Exception:
            hash = None
            url = False
    if file: hash = getMD5(path=file_path)
    if not (hash and file): hash = file_path
    try:
        report = get_report(hash, url)
        if report:
            LOGGER.info("VirusTotal -  Report found.")
            LOGGER.info(report)
            if int(report['response_code']) == 1:
                return report
            elif file_path:
                LOGGER.info("VirusTotal -  file upload")
                upload_response = upload_file(file_path, url)
                return upload_response
    except Exception as e: LOGGER.error(e)




def validateValue(result, value):
    try: return result[value]
    except: return False


def getResultAsReadable(result):
    if not result:
        LOGGER.error(result)
        return "Something went wrong. Check Logs."
    someInfo = ""
    if validateValue(result, 'verbose_msg'):
        go = None if "Scan finished" in result['verbose_msg'] else result['verbose_msg']
        if go: someInfo += f"\nMessage: <code>{go}</code>"
    if validateValue(result, 'scan_id'): someInfo += f"\nScan ID: <code>{result['scan_id']}</code>"
    if validateValue(result, 'scan_date'): someInfo += f"\nDate: <code>{result['scan_date']}</code>"
    if validateValue(result, 'md5'): someInfo += f"\nMD5: <code>{result['md5']}</code>"
    if validateValue(result, 'sha1'): someInfo += f"\nSHA1: <code>{result['sha1']}</code>"
    if validateValue(result, 'sha256'): someInfo += f"\nSHA256: <code>{result['sha256']}</code>"
    if validateValue(result, 'permalink'): someInfo += f"\nLink: {short_url(result['permalink'])}"
    if validateValue(result, 'scans'):
        pos = []
        neg = []
        scans = result['scans']
        for i in scans:
            if bool((scans[i]['detected'])): pos.append(i) 
            else: neg.append(i)
        tore = someInfo + "\n\nTotal: " + str(result['total'])  + \
            " | Positives: " + str(result['positives']) + \
            " | Negatives: " + str(len(neg))
        if len(pos) > 0: tore += "\nDetections: <code>" + ", ".join(pos) + "</code>"
        return tore
    else: return someInfo


def humanbytes(size, byte=True):
    """Hi human, you can't read bytes?"""
    if not byte: size = size / 8 # byte or bit ?
    power = 2 ** 10
    zero = 0
    units = {0: "", 1: "KiB", 2: "MiB", 3: "GiB", 4: "TiB"}
    while size > power:
        size /= power
        zero += 1
    return f"{round(size, 2)} {units[zero]}"


def virustotal(update, context):
    if not VIRUSTOTAL_API: return LOGGER.error("VirusTotal - VIRUSTOTAL_API not provided.")
    message = update.effective_message
    VtPath = os.path.join("Virustotal", str(message.from_user.id))
    if not os.path.exists("Virustotal"): os.makedirs("Virustotal")
    if not os.path.exists(VtPath): os.makedirs(VtPath)
    help_msg = "<b>Reply to message including file:</b>"
    help_msg += f"\n<code>/{BotCommands.VirusTotalCommand}" + " {message}" + "</code>"
    help_msg += "\n<b>By replying to message (including hash):</b>"
    help_msg += f"\n<code>/{BotCommands.VirusTotalCommand}" + " {message}" + "</code>"
    link = None
    if message.reply_to_message:
        if message.reply_to_message.document: # file
            maxsize = 210*1024*1024
            if VIRUSTOTAL_FREE: maxsize = 32*1024*1024
            if message.reply_to_message.document.file_size > maxsize:
                return sendMessage(f"File limit is {humanbytes(maxsize)}", context.bot, update)
            try:
                sent = sendMessage(f"Trying to download. Please wait.", context.bot, update)
                filename = os.path.join(VtPath, message.reply_to_message.document.file_name)
                link = app.download_media(message=message.reply_to_message.document, file_name=filename)
            except Exception as e: LOGGER.error(e)
        else: link = message.reply_to_message.text
    else:
        link = message.text.split(' ', 1)
        if len(link) != 2: link = None
        else: link = link[1]
    if not link: editMessage(help_msg, sent)
    ret = getResultAsReadable(get_result(link))
    try: os.remove(link)
    except: pass
    return editMessage(ret, sent)


virustotal_handler = CommandHandler(BotCommands.VirusTotalCommand, virustotal,
    filters=CustomFilters.authorized_chat | CustomFilters.authorized_user, run_async=True)
dispatcher.add_handler(virustotal_handler)
