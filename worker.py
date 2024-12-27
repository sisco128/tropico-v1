# worker.py
import os
from rq import Worker, Queue, Connection
from redis import Redis

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
listen = ["default"]

redis_conn = Redis.from_url(REDIS_URL)

if __name__ == "__main__":
    with Connection(redis_conn):
        worker = Worker(map(Queue, listen))
        worker.work()
