import asyncio
import json
import random
import re
from datetime import datetime, timedelta

import aiohttp
from Crypto.Cipher import AES
from aiogram import Bot, types
from aiogram.utils.markdown import hcode
from bs4 import BeautifulSoup

df_id_pattern = re.compile(
    r'document\.cookie\s*=\s*"([^="]+)="\s*\+\s*toHex\(slowAES\.decrypt\(toNumbers\(\"([0-9a-f]{32})\"\)', re.MULTILINE)


async def read_config():
    with open('config.json', 'r') as f:
        config = json.load(f)
        return config


def set_df_uid(soup):
    with open('index.html', 'w') as f:
        f.write(str(soup))
    noscript = soup.find("noscript")
    if not noscript:
        return False
    pstring = noscript.find("p")
    if not (
            pstring
            and pstring.string
            == "Oops! Please enable JavaScript and Cookies in your browser."
    ):
        return False
    script = soup.find_all("script")
    if not script:
        return False
    if not (
            script[1].string.startswith(
                'var _0xe1a2=["\\x70\\x75\\x73\\x68","\\x72\\x65\\x70\\x6C\\x61\\x63\\x65","\\x6C\\x65\\x6E\\x67\\x74\\x68","\\x63\\x6F\\x6E\\x73\\x74\\x72\\x75\\x63\\x74\\x6F\\x72","","\\x30","\\x74\\x6F\\x4C\\x6F\\x77\\x65\\x72\\x43\\x61\\x73\\x65"];function '
            )
            and script[0].get("src") == "/aes.js"
    ):
        return False
    match = df_id_pattern.search(script[1].string)

    cipher = AES.new(
        bytearray.fromhex("e9df592a0909bfa5fcff1ce7958e598b"),
        AES.MODE_CBC,
        bytearray.fromhex("5d10aa76f4aed1bdf3dbb302e8863d52"),
    )

    return {match.group(1): cipher.decrypt(bytearray.fromhex(match.group(2))).hex()}


async def get_random_user_agent():
    async with aiohttp.ClientSession() as session:
        async with session.get('http://www.useragentstring.com/pages/useragentstring.php?name=Chrome') as response:
            soup = BeautifulSoup((await response.text()), 'html.parser')
            useragents = []
            for i in soup.find_all('a'):
                if str(i.text).startswith('Mozilla/5.0'):
                    useragents.append(i.text)
            return random.choice(useragents)


def get_xfToken(*, response_text):
    try:
        return response_text.split('name="_xfToken" value="')[1].split('"')[0]
    except:
        return False


async def up_thread(thread_id, session: aiohttp.ClientSession, bot: Bot, owner_id: int, timeout: int,
                    logs: int, send_timeout: int):
    xftoken = await session.get('https://lolz.guru/?tab=mythreads')
    xftoken = get_xfToken(response_text=str((await xftoken.text())))
    async with session.get(f'https://lolz.guru/threads/{thread_id}/bump?from_list=1&&_xfRequestUri=%2F%3Ftab%3Dmythreads&_xfNoRedirect=1&_xfToken={xftoken}&_xfResponseType=json') as response:
        response = await response.json()
        msg = hcode(f'{json.dumps(response, indent=4, sort_keys=True, ensure_ascii=False)}')
        if logs == 2:
            await bot.send_message(owner_id,
                                   f'<b>Запрос для поднятия темы https://lolz.guru/threads/3585935/ успешно отправлен!</b>\n\nОтправил запрос: <code>{datetime.now()}</code>\nСледующий запрос будет отправлен: <code>{datetime.now() + timedelta(seconds=send_timeout)}</code>\n\nОтвет от сервера:\n\n' + msg)
        elif logs == 1:
            if response.get('status') == 'ok':
                await bot.send_message(owner_id,
                                       f'Запрос на поднятие темы успешно отправлен и принят! Тема была успешно поднята!\n\nОтправил запрос: <code>{datetime.now()}</code>\nСледующий запрос будет отправлен: <code>{datetime.now() + timedelta(seconds=send_timeout)}</code>\n\nОтвет от сервера:\n\n' + msg)
    await asyncio.sleep(timeout)


async def main():
    config = await read_config()
    headers = {
        'authority': 'lolz.guru',
        'accept': 'application/json, text/javascript, */*; q=0.01',
        'accept-language': 'ru,en;q=0.9',
        'referer': 'https://lolz.guru/?tab=mythreads',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="102", "Yandex";v="22"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': await get_random_user_agent(),
        'x-ajax-referer': 'https://lolz.guru/?tab=mythreads',
        'x-requested-with': 'XMLHttpRequest',
    }
    cookies = {
        'xf_tfa_trust': config['cookies']['xf_tfa_trust'],
        'xf_user': config['cookies']['xf_user'],
        'xf_logged_in': '1',
    }
    bot = Bot(config['bot_settings']['token'], parse_mode=types.ParseMode.HTML)
    async with aiohttp.ClientSession(headers=headers, cookies=cookies) as session:
        response = await session.get('https://lolz.guru/', cookies=cookies, headers=headers)
        cook = set_df_uid(BeautifulSoup(await response.text(), 'html.parser'))
        cookies.update(cook)
        response.close()
        session.cookie_jar.update_cookies(cookies)
        while True:
            for thread_id in [re.search(pattern='https?://lolz\.guru/threads/(\d+)/?', string=i).group(0).split('/')[4]
                              for i in config['settings']['thread_urls']]:
                await up_thread(thread_id=thread_id, session=session,
                                bot=bot, owner_id=config['bot_settings']['owner_id'],
                                timeout=config['settings']['thread_timeout'], logs=config['bot_settings']['logs'], send_timeout=config['settings']['timeout'])
            await asyncio.sleep(int(config['settings']['timeout']))


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
