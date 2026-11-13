# EVM Portfolio Checker — только чтение

Проверка нативных монет и **заранее известных контрактов ERC-20/BEP-20** в 18 EVM-сетях. Не требует приватных ключей, не отправляет транзакции, не подписывает ничего.

## Установка и запуск

```bash
cd evm_portfolio_checker
python3 -m venv .venv
source .venv/bin/activate  # macOS / Linux
python -m pip install -r requirements.txt
```

Заполните `addresses.txt`: по одному **публичному** `0x`-адресу на строку. Можно оставлять комментарии `#` или `//`.

```bash
python checker.py --probe-only                 # проверьте RPC
python checker.py --usd                        # полный скан + ориентировочная USD-оценка
python checker.py --only ethereum,base,bsc    # тест нескольких сетей
```

В Windows: `.venv\\Scripts\\activate` вместо `source .venv/bin/activate`.

Файлы в `reports/`:
- `balances_all.csv` — **все** попытки с нулями и ошибками (ошибки не становятся нулём).
- `balances_nonzero.csv` — найденные ненулевые позиции.
- `summary_by_address.csv` — количество активов/сетей, известная сумма USD, ошибки.
- `summary_by_network.csv` — сети, количество ненулевых позиций, ошибки.
- `summary_by_asset.csv` — суммы активов по сети и адресу контракта.
- `errors.csv` — неуспешные проверки для повторного запуска.
- `rpc_health.json` — статистика RPC. `rpc_probes.json` после `--probe-only`.
- `summary.json` — сводка. Поле known_usd_total **не является полной стоимостью**, если присутствуют nonzero активы без цены.

## RPC и отказоустойчивость

`networks.json` содержит **82 публичных RPC-кандидата**: от **3 до 5** на сеть. Пять удалось собрать не для каждой: не выдумываем несуществующие URL. `checker.py --probe-only` проверит `eth_chainId` и номер блока; при сканировании недоступный RPC заменяется следующим. Кандидат с неправильным chainId исключается. Провайдеры могут ограничивать доступ: отсутствие ошибки на все времена невозможно.

Для сетей с <5 RPC можно создать `extra_rpcs.json` (смотри `extra_rpcs.example.json`) и внести свои действительные адреса сервисов. Дополнительные кандидаты добавляются до пяти. **Не размещайте RPC URL с секретным API-ключом в общедоступном репозитории.**

Если все RPC не сработали, строка будет `ERROR`, а не `0`. Чтобы не перегружать бесплатные сервисы, число параллельных запросов небольшое; параметры можно настраивать.

## Токены: что покрывает и что не покрывает

`tokens.json` — стартовый проверенный список **65 контрактов**, в том числе USDC/USDC.e, USDT/USDT0, USDB, WETH, DAI, WBTC, LINK, UNI, FDUSD, GNO, USDe и варианты Binance-Peg, на тех сетях, где указаны адреса. Скрипт сам читает `decimals()` у контракта, потому что USDT может иметь разное число знаков в разных сетях. Чтобы добавить токен, внесите в `tokens.json` соответствующей сети:

```json
{"symbol":"MYTOKEN","address":"0x..."}
```

**Важно:** обычный публичный RPC не умеет ответить на вопрос «перечисли вообще все ERC-20 токены кошелька». Для полного инвентаря нужен индексатор по адресам (или история всех событий `Transfer` и проверка актуальных `balanceOf`), а для DeFi позиций, LP, стейкинга и NFT — дополнительные адаптеры. Классический ERC-20-скан без индексатора может пропустить активы. Не использовать его как единственное основание для перевода всех средств.

Автоматический поиск произвольных токенов без проверки может собрать спам/фальшивые токены. Контракты сверяйте с первоисточниками — например Circle/Tether.

## USD-оценка

При `--usd` запрашивает ориентировочные цены в DefiLlama. Нет цены / нет связи — пустое поле, а не `0 USD`. Сумма `known_usd_total` — только оценённая часть. Нельзя складывать одинаковые тикеры из разных сетей без учёта контракта: `summary_by_asset.csv` сохраняет сеть и контракт.

## Дальнейший этап — консолидация только своих кошельков

Это **не** модуль переводов. Будущий отдельный модуль должен иметь `dry-run` по умолчанию, явный подтверждённый адрес получателя, chainId, список разрешённых исходных адресов и транзакций, оценку и резерв gas, контроль nonce, повторную проверку баланса перед подписанием, мониторинг receipt, журнал и остановку при любой неоднозначности. ERC-20 переводить **до** нативной монеты; иначе для ERC-20 может не остаться газа. Не хранить приватные ключи в `addresses.txt`, CSV, логах или Git.

Если нужно вывести активы с разных сетей **в одну сеть**, мало указать один 0x-адрес: потребуется отдельный сценарий cross-chain bridge / обмена с учётом комиссий и рисков.

## Источники конфигурации (сверять актуальность)

- https://chainlist.org
- https://api.pocket.network/
- https://blockmachine.io/public-rpc-endpoints
- https://nodeflare.app/chains
- https://developer.arbitrum.io/chain-info
- https://docs.bnbchain.org/bnb-opbnb/get-started/network-info/
- https://developers.circle.com/stablecoins/usdc-contract-addresses
- https://tether.to/en/supported-protocols/
- https://docs.llama.fi/list-your-project/how-to-request-token-pricing

**Ограничение:** значения RPC и токенов собраны из доступных источников, но не проверены живыми запросами из этой среды. Команда `--probe-only` нужна для их проверки в вашей сети перед использованием.

Дополнительные источники адресов: https://developers.uniswap.org/docs/unichain/technical-information/contract-addresses ; https://docs.gnosischain.com/bridges/management/decisions ; https://docs.scroll.io/en/developers/scroll-contracts/ ; https://github.com/bnb-chain/opbnb-bridge-tokens ; https://www.circle.com/blog/now-live-native-usdc-and-cctp-v2-on-sonic .
