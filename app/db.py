"""SQLite 数据访问层。

- 显式事务：写操作在 BEGIN IMMEDIATE 事务中进行，防止答卷与结算并发竞态。
- 所有时间戳统一为服务端 Unix 秒（INTEGER）。
"""

import json
import os
import sqlite3
import time
from contextlib import contextmanager

DB_PATH = os.environ.get("SNIFF_DB_PATH", "/data/sniff.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tests (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    code               TEXT NOT NULL UNIQUE,          -- 负责人管理码
    token_hash         TEXT NOT NULL,                 -- 负责人令牌哈希
    sample_a           TEXT NOT NULL,
    sample_b           TEXT NOT NULL,
    deadline           INTEGER NOT NULL,
    min_valid          INTEGER NOT NULL,
    created_at         INTEGER NOT NULL,
    settled_at         INTEGER,
    valid_count        INTEGER,
    correct_count      INTEGER,
    p_value            REAL,
    distinguishable    INTEGER
);

CREATE TABLE IF NOT EXISTS assignments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id      INTEGER NOT NULL REFERENCES tests(id),
    panelist     TEXT NOT NULL,
    code         TEXT NOT NULL UNIQUE,                -- 评员盲评码
    odd_pos      INTEGER NOT NULL,                    -- 异样杯位置 1/2/3
    odd_sample   TEXT NOT NULL,                       -- 异样杯样本编号（A 或 B）
    answer       INTEGER,                             -- 1/2/3；弃权为 -1；未提交 NULL
    answered_at  INTEGER,
    status       TEXT NOT NULL DEFAULT 'active',      -- active 有效名单；withdrawn 已撤回
    UNIQUE(test_id, panelist)
);

CREATE INDEX IF NOT EXISTS idx_assignments_test ON assignments(test_id);

-- 操作时间线：创建 / 名单调整 / 答卷 / 弃权 / 结算，一笔一条，与状态变更同事务提交
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id    INTEGER NOT NULL REFERENCES tests(id),
    seq        INTEGER NOT NULL,                -- 实验内单调递增序号（提交顺序）
    at         INTEGER NOT NULL,                -- 服务端 Unix 秒
    type       TEXT NOT NULL,                   -- created/roster_adjusted/answer/abstain/settled/recording_started
    panelist   TEXT,                            -- 关联评员（答卷/弃权），其余为 NULL
    payload    TEXT NOT NULL DEFAULT '{}'       -- JSON 明细（结果）
);

CREATE INDEX IF NOT EXISTS idx_events_test ON events(test_id, seq);
"""

# 旧库迁移标记：events 表为空而 tests 已有数据时，为每个既有实验补一条
# “记录起点”事件——此前发生的操作无记录，也绝不虚构历史。
_RECORDING_STARTED_NOTE = (
    "系统升级前数据：此前的创建、答卷、调整与结算无逐笔记录，时间线自此开始"
)


def connect():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = connect()
    try:
        conn.executescript(_SCHEMA)
        # 兼容旧库：为已存在的 assignments 表补 status 列
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(assignments)")}
        if "status" not in cols:
            conn.execute(
                "ALTER TABLE assignments ADD COLUMN status TEXT NOT NULL "
                "DEFAULT 'active'"
            )
        # 兼容旧库：既往实验没有时间线记录。为每个既有实验补一条
        # recording_started 起点事件（时间为迁移时刻），明确标示记录起点，
        # 不回填、不虚构任何既往操作。
        events_empty = conn.execute(
            "SELECT 1 FROM events LIMIT 1"
        ).fetchone() is None
        if events_empty:
            legacy = conn.execute("SELECT id FROM tests ORDER BY id").fetchall()
            for t in legacy:
                conn.execute(
                    "INSERT INTO events (test_id, seq, at, type, panelist, payload)"
                    " VALUES (?, 1, ?, 'recording_started', NULL, ?)",
                    (t["id"], int(time.time()),
                     json.dumps({"note": _RECORDING_STARTED_NOTE},
                                ensure_ascii=False)),
                )
        conn.commit()
    finally:
        conn.close()


@contextmanager
def write_tx():
    """立即拿写锁的事务；异常回滚，正常提交。"""
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def read_conn():
    return connect()


def log_event(conn, test_id: int, type_: str, panelist=None, payload=None):
    """在既有写事务内追加一条时间线事件（与状态变更同一事务，原子提交）。

    seq 为实验内单调递增序号：所有写都在 BEGIN IMMEDIATE 事务中串行完成，
    因此 seq 顺序即事务提交顺序，与最终状态一致。调用方校验失败抛异常时，
    整个事务回滚，不会留下事件记录。
    """
    seq = conn.execute(
        "SELECT COALESCE(MAX(seq), 0) + 1 AS s FROM events WHERE test_id = ?",
        (test_id,),
    ).fetchone()["s"]
    conn.execute(
        "INSERT INTO events (test_id, seq, at, type, panelist, payload)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (test_id, seq, int(time.time()), type_, panelist,
         json.dumps(payload or {}, ensure_ascii=False)),
    )
