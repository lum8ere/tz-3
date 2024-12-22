### Настройте `env` файла
Создайте папку envs в корне проекта, в ней создайте `local.env` и добавьте следующие переменные:

```bash
DATABASE_URL="postgresql://postgres:root@localhost:5432/postgres?statement_timeout=120000"
JWT_SECRET=aa5d6faf3481cbfbd3a5b3d87005b30d36389f3cddd2fdedc773fe7f3b6fbbd0
LOG_LEVEL=debug
LOG_TO_CONSOLE=true
```