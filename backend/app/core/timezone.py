from datetime import datetime

import pytz
from sqlalchemy import DateTime, TypeDecorator

WIB = pytz.timezone("Asia/Jakarta")


def now_wib() -> datetime:
    return datetime.now(WIB)


def as_wib(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return WIB.localize(value)
    return value.astimezone(WIB)


class WIBDateTime(TypeDecorator):
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        value = as_wib(value)
        return value.replace(tzinfo=None) if value else None

    def process_result_value(self, value, dialect):
        return as_wib(value)
