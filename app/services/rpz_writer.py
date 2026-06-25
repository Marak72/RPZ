"""ЗАГЛУШКА: выгрузка новых доменов в RPZ-зону BIND по SSH.

Реализуется в самой последней фазе проекта. Сейчас функция намеренно
сообщает, что функционал ещё не готов.

Будущая реализация (план):
  1. Подключиться по SSH под учётной записью SshServer.
  2. Дозаписать в файл зоны строки вида:
         <domain> CNAME rpz-drop.
         *.<domain> CNAME rpz-drop.
  3. Инкрементировать serial в SOA.
  4. Выполнить `rndc reload <zone>`.
  5. Перевести соответствующие BlockEntry в статус "pushed".
"""


class NotImplementedYet(Exception):
    pass


def push_entries(server, entries) -> None:
    """Выгрузить домены на сервер. Пока не реализовано."""
    raise NotImplementedYet(
        "Выгрузка на сервер BIND будет реализована в финальной фазе проекта."
    )
