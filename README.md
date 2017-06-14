Основано на коде extfilter_maker https://github.com/max197616/extfilter/tree/master/scripts/extfilter-maker

Генерирует файлы для UNBOUND для работы с блокировками РКН для повышения качества блокировок и экономии ресурсов используемого DPI.

Для подключения файлов в конфиг unbound нужно добавить
  include: /etc/unbound/forward.conf
  include: /etc/unbound/domains_mask.conf
