package main

import (
	"os"
	"strings"
)

const languageEnvironment = "LOBOTOMY_PROXY_LANGUAGE"

func message(english string) string {
	return translated(os.Getenv(languageEnvironment), english)
}

func translated(language, english string) string {
	if language == "ru" {
		if text, ok := russianMessages[english]; ok {
			return text
		}
	}
	return english
}

func browserLanguage(header string) string {
	if header == "" && os.Getenv(languageEnvironment) == "ru" {
		return "ru"
	}
	first, _, _ := strings.Cut(header, ",")
	tag, _, _ := strings.Cut(first, ";")
	primary, _, _ := strings.Cut(strings.TrimSpace(tag), "-")
	if strings.EqualFold(primary, "ru") {
		return "ru"
	}
	return "en"
}

var russianMessages = map[string]string{
	"App profile → local proxy":                                      "Профиль приложения → локальный прокси",
	"Berlin DNS is unavailable: %w":                                  "берлинский DNS недоступен: %w",
	"Berlin DNS returned HTTP %d (%s)":                               "берлинский DNS вернул HTTP %d (%s)",
	"Browser check":                                                  "Проверка браузера",
	"Browser policy → local proxy":                                   "Политика браузера → локальный прокси",
	"CNAME chain is too long":                                        "слишком длинная цепочка CNAME",
	"Checking the system route":                                      "Проверка системного маршрута",
	"DNS conflict for %s":                                            "конфликт DNS для %s",
	"DNS did not return a public destination address":                "DNS не вернул публичный адрес назначения",
	"DNS error: %v":                                                  "ошибка DNS: %v",
	"Enter the proxy’s numeric IP address to use Berlin DNS.":        "Для берлинского DNS укажите числовой IP подключения к прокси.",
	"Exit time zone at setup":                                        "Часовой пояс выхода при установке",
	"Exit verified":                                                  "Выход подтверждён",
	"Filter route verified":                                          "Маршрут фильтра подтверждён",
	"Forwarding is blocked. Check the service and domain DNS rules.": "Передача закрыта. Проверьте службу и доменные правила DNS.",
	"JavaScript is disabled":                                         "JavaScript выключен",
	"Net.Coffee could not verify the DNS address":                    "Net.Coffee не подтвердил адрес DNS",
	"Route for this request":                                         "Маршрут этого запроса",
	"SOCKS5 rejected the authentication method":                      "SOCKS5 отклонил метод авторизации",
	"SOCKS5 rejected the connection":                                 "SOCKS5 отклонил соединение",
	"SOCKS5 rejected the username or password":                       "SOCKS5 отклонил логин или пароль",
	"System DNS → local service":                                     "Системный DNS → локальная служба",
	"TLS connection to the proxy failed":                             "ошибка TLS до прокси",
	"TLS verification of the diagnostic service failed":              "ошибка проверки TLS диагностического сервиса",
	"The exit time zone changed.":                                    "Изменился часовой пояс выхода.",
	"The proxy rejected the connection. Forwarding is blocked.":      "Прокси отклонил соединение. Передача закрыта.",
	"The time zones differ.":                                         "Часовые пояса различаются.",
	"The time zones match.":                                          "Часовые пояса совпадают.",
	"The verification result expired.":                               "Истёк результат проверки.",
	"This page was served by your Mac. The result applies to this window and address.": "Страница загружена с этого Mac. Проверка относится к этому окну и этому адресу.",
	"Time zone reported by this browser":                                               "Часовой пояс, который передаёт браузер",
	"a separate DNS configuration already exists for %s":                               "уже есть отдельный DNS для %s",
	"address blocked by a rule":                                                        "адрес закрыт правилом",
	"administrator privileges are required":                                            "требуются права администратора",
	"an external hosts entry already exists for %s":                                    "есть внешняя запись hosts для %s",
	"another user owns the rules":                                                      "правила принадлежат другому пользователю",
	"another user owns the time zone setting":                                          "настройка пояса принадлежит другому пользователю",
	"apply the updated filter":                                                         "примените обновлённый фильтр",
	"changing the time zone: %w":                                                       "смена часового пояса: %w",
	"check the last line of the hosts file":                                            "проверьте последнюю строку hosts",
	"check the port, username, and password":                                           "проверьте порт, логин и пароль",
	"check the user and the exit time zone":                                            "проверьте пользователя и пояс выхода",
	"could not connect to the proxy":                                                   "нет соединения с прокси",
	"could not determine the exit time zone":                                           "не удалось определить часовой пояс выхода",
	"could not determine the user’s group":                                             "не удалось определить группу пользователя",
	"could not read the Mac’s time zone":                                               "не удалось прочитать часовой пояс Mac",
	"could not verify ownership of the settings":                                       "не удалось подтвердить владельца настройки",
	"could not verify ownership of the system rules":                                   "не удалось подтвердить владельца системных правил",
	"could not verify the time zone":                                                   "не удалось проверить часовой пояс",
	"diagnostic service %s returned HTTP %d":                                           "диагностика %s вернула HTTP %d",
	"diagnostic services reported different exits":                                     "диагностические сервисы видят разные выходы",
	"domain rule files changed; check the conflict before rolling back":                "файлы доменных правил изменились. Проверьте конфликт перед откатом",
	"domain rules were preserved and forwarding is blocked":                            "доменные правила сохранены, передача закрыта",
	"file changed externally and was preserved: %s":                                    "файл изменён отдельно, сохранён: %s",
	"filter update required":                                                           "требуется обновление фильтра",
	"finish rolling back the interrupted update":                                       "завершите откат прерванного обновления",
	"forwarding is already running in another window":                                  "передача уже запущена в другом окне",
	"forwarding is blocked":                                                            "передача закрыта",
	"installation is already in progress":                                              "установка уже выполняется",
	"installed worker failed verification":                                             "установленный обработчик не прошёл проверку",
	"invalid DNS response":                                                             "неверный ответ DNS",
	"invalid SOCKS5 response":                                                          "некорректный ответ SOCKS5",
	"invalid address":                                                                  "неверный адрес",
	"invalid destination address":                                                      "неверный адрес назначения",
	"invalid domain: %q":                                                               "некорректный домен: %q",
	"invalid exit time zone":                                                           "неверный пояс выхода",
	"invalid owner or permissions on directory %s":                                     "некорректный владелец или права папки %s",
	"invalid public IP":                                                                "неверный внешний IP",
	"invalid server name":                                                              "некорректное имя сервера",
	"invalid socket directory":                                                         "неверная папка канала",
	"invalid time zone":                                                                "некорректный часовой пояс",
	"invalid time zone mode":                                                           "неверный режим пояса",
	"local IP address already in use":                                                  "локальный IP уже занят",
	"macOS rules are not installed yet":                                                "правила macOS ещё не установлены",
	"malformed DNS response":                                                           "повреждённый ответ DNS",
	"nonstandard resolver directory":                                                   "нестандартная папка resolver",
	"path already in use: %s":                                                          "путь уже занят: %s",
	"proxy returned HTTP %d":                                                           "прокси ответил HTTP %d",
	"remaining files in the working directory were preserved":                          "в рабочей папке остались файлы; они сохранены",
	"requested time zone %s, but macOS reports %s. Run the check again in Connection":  "запрошен пояс %s, macOS сообщает %s. Повторите проверку в «Подключении»",
	"system service unavailable":                                                       "системная служба недоступна",
	"the DNS configuration for %s was changed externally":                              "DNS для %s был изменён отдельно",
	"the Lobotomy Proxy section in hosts is damaged":                                   "повреждена секция Lobotomy Proxy в hosts",
	"the hosts section was changed externally":                                         "секция hosts была изменена отдельно",
	"the previous installation’s section was not found":                                "секция предыдущей установки не найдена",
	"the server IP must be numeric":                                                    "IP сервера должен быть числовым",
	"the service configuration was changed externally":                                 "настройка службы изменена отдельно",
	"the service could not bind the local ports":                                       "служба не смогла занять локальные порты",
	"the service definition was changed externally":                                    "описание службы изменено отдельно",
	"the service executable was changed externally":                                    "исполняемый файл службы изменён отдельно",
	"too many domains":                                                                 "слишком много доменов",
	"unexpected DNS server address":                                                    "неожиданный адрес DNS-сервера",
	"unexpected file type at %s":                                                       "необычный тип файла %s",
	"unknown DNS mode":                                                                 "неизвестный режим DNS",
	"unknown proxy type":                                                               "неизвестный тип прокси",
	"unrecognized entries in the previous hosts section":                               "посторонние записи в прежней секции hosts",
	"unsupported or duplicate app":                                                     "неподдерживаемое или повторяющееся приложение",
}
