import json
import os
from datetime import datetime, timezone

import redis
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv()

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = "swarmsec"

# Redis channel  ->  MongoDB collection
CHANNELS = {
    "swarmsec:detections": "detections",  # from detection_agent.py
    "swarmsec:context": "contexts",       # from graph_context_agent.py
}


def main():
    mongo = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
    mongo.admin.command("ping")  # fail fast if MongoDB is not reachable
    db = mongo[DB_NAME]

    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    pubsub = r.pubsub()
    pubsub.subscribe(*CHANNELS.keys())
    print(f"Mongo logger ready. Channels: {list(CHANNELS)} -> db '{DB_NAME}'")

    for message in pubsub.listen():
        if message["type"] != "message":
            continue

        try:
            doc = json.loads(message["data"])
        except json.JSONDecodeError:
            doc = {"raw": message["data"]}

        doc["logged_at"] = datetime.now(timezone.utc)
        collection = CHANNELS[message["channel"]]
        db[collection].insert_one(doc)

        total = db[collection].count_documents({})
        print(f"[mongo-logger] saved to {collection} (total now: {total})")


if __name__ == "__main__":
    main()