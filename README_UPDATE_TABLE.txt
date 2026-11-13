ОБНОВЛЕНИЕ: интерактивные таблицы кошельков

1. Скопируйте checker.py и report_view.py из архива в существующую папку evm_portfolio_checker, заменив checker.py.
2. Не трогайте ваши addresses.txt, tokens.json, networks.json и extra_rpcs.json.
3. В терминале из папки проекта выполните:
       python checker.py --report-only
       open reports/portfolio.html
   Это построит таблицу из уже готового reports/balances_all.csv БЕЗ обращений к RPC.
4. При следующем полном запуске python checker.py --usd таблица автоматически обновится.

Новые файлы в reports:
portfolio.html — интерактивная таблица в браузере, фильтры/поиск/сортировка/детали
wallets_table.csv — одна строка на кошелёк, столбцы по сетям с токенами и USD
wallets_by_network.csv — одна строка на кошелёк и сеть
wallet_assets.csv — все ненулевые активы с количеством и USD

Оригинальные CSV не удаляются. Стоимость USD лишь известная часть;
ошибки Ethereum из вашего примера не превращаются в нули.
Никаких транзакций обновление не отправляет.
