import telebot
import requests
import socket
import json
from shodan import Shodan
from censys.search import CensysHosts
from pathlib import Path

# тег бота: @UniitShodunBot
bot = telebot.TeleBot('5877928916:AAHWzT4YLy9UNaOCQOtp1dTRH-7GK3wIneM')  # Telegram bot token
api = Shodan('5IzE5XrF0qjDPPGevvuCRJ0AcpFCekri')  # Shodan token
chat_id = -858519698  # Место отправки сообщений
censys_host = CensysHosts()
# list_of_dom_names_and_ipV4 = ''
# ips = list()

# Get ips
file = open("ips.txt")
domens = list([w for w in Path('ips.txt').read_text(encoding="utf-8").replace("\n", " ").split()])

# Start(/list) message
list_start_message = ''
i = 0
ips = []
for domen in domens:
    list_start_message += str(i) + '. ' + domen + ', ' + socket.gethostbyname(domen) + '\n'
    ips.append(socket.gethostbyname(domen))
    i = i + 1

@bot.message_handler(func=lambda message: message.chat.id != chat_id)
def protect_from_strangers(message):
   pass


@bot.message_handler(commands=['list'])
def start(message):
    bot.send_message(chat_id, list_start_message)


# Shodan
api = Shodan('5IzE5XrF0qjDPPGevvuCRJ0AcpFCekri')


@bot.message_handler(content_types=['text'])
def handle_text(message):
    if message.text.isdigit():
        int_message = int(message.text)
        if (int_message >= 0) & (int_message <= len(domens)):
            requested_ip = socket.gethostbyname(domens[int_message])  # адрес из листа
            request = api.host(requested_ip)
            print(request)
            reply = ''
            if str(request['ports']) != str([80, 443]):
                for obj in request['ports']:
                    reply += str(obj) + ', '
                reply = reply[0:-2]
            else:
                reply += 'Порты норм'
            bot.send_message(chat_id, reply)
        else:
            bot.send_message(chat_id, "Значения нет")
    else:
        bot.send_message(chat_id, "Значение не то")


# AbuseIpDb
url = 'https://api.abuseipdb.com/api/v2/check'
#5.141.28.183
#45.93.16.32
querystring = {
    'ipAddress': '5.141.28.183',
    'maxAgeInDays': '365'
}

headers = {
    'Accept': 'application/json',
    'Key': 'bf5f99dad0962181e1fad775d25ab1ad08cbbc0bb12642052bece9ceba742b1cc19c1b417231b445'
}

response = requests.request(method='GET', url=url, headers=headers, params=querystring)

decodedResponse = json.loads(response.text)
smsWL = ''
if str(decodedResponse['data']['isWhitelisted']) == 'true':
    smsWL = 'Адрес также имеется в белом списке.'
elif str(decodedResponse['data']['isWhitelisted']) == 'false': 
    smsWL = 'Адреса нет в белом списке.'
else:
    smsWL = 'Поиск по белому списку не производился'
bot.send_message(chat_id, 'Показатель доверия (100 - это плохо, 0 - все окей): ' + str(decodedResponse['data']['abuseConfidenceScore'])+ '\n' + 'Число репортов: ' + str(decodedResponse['data']['totalReports']) + '\n' + smsWL)

#Проверка на наличие в черном списке
urlBlackList = 'https://api.abuseipdb.com/api/v2/blacklist'

querystringBL = {
    'confidenceMinimum':'99'
}
blmes = ''
response = requests.request(method='GET', url=urlBlackList, headers=headers, params=querystringBL)
decodedResponseBL = json.loads(response.text)

def check_value(data, val):
    return any(ipv['ipAddress']==val for ipv in data['data'])

if check_value(decodedResponseBL, "5.141.28.183") == True:
    blmes = 'Данные ipv4 найден в черном списке!'
elif check_value(decodedResponseBL, "5.141.28.183") == False:
    blmes = 'Не найдено в черном списке.'

print(blmes)
bot.send_message(chat_id, blmes)


# censys part
hosts = censys_host.bulk_view(ips)
# print(hosts) высирает очень большой json)) но зато все айпи проверяет


if __name__ == '__main__':
    bot.infinity_polling()
