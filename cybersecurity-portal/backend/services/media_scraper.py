import feedparser
import logging
import time
from datetime import datetime
from database import SessionLocal
from models import MediaItem

logger = logging.getLogger("media_scraper")

SOURCES = [
    # YouTube (video)
    {"url": "https://www.youtube.com/feeds/videos.xml?channel_id=UCVeW9qkBjo3zosnqUbG7CFw", "type": "video", "source": "John Hammond"},
    {"url": "https://www.youtube.com/feeds/videos.xml?channel_id=UC9x0AN7BWHpXC1IGamAHk7A", "type": "video", "source": "NetworkChuck"},
    {"url": "https://www.youtube.com/feeds/videos.xml?channel_id=UC6PTgowOUJV74zEQy5QqqTQ", "type": "video", "source": "DEF CON"},
    {"url": "https://www.youtube.com/feeds/videos.xml?channel_id=UClcE-kVhqyiHCcjYwcpfj9w", "type": "video", "source": "LiveOverflow"},
    {"url": "https://www.youtube.com/feeds/videos.xml?channel_id=UCNbNGqL1eS6iF5K8uJ2KhtA", "type": "video", "source": "David Bombal"},
    {"url": "https://www.youtube.com/feeds/videos.xml?channel_id=UC3s0BtrBJpwNDaflRSoiieQ", "type": "video", "source": "Hak5"},
    
    # Podcasts (podcast)
    {"url": "https://feeds.megaphone.fm/darknetdiaries", "type": "podcast", "source": "Darknet Diaries"},
    {"url": "https://thecyberwire.libsyn.com/rss", "type": "podcast", "source": "CyberWire Daily"},
    {"url": "https://feed.podbean.com/securityweekly/feed.xml", "type": "podcast", "source": "Security Weekly"},
    
    # News (article)
    {"url": "https://www.bleepingcomputer.com/feed/", "type": "article", "source": "BleepingComputer"},
    {"url": "https://feeds.feedburner.com/TheHackersNews", "type": "article", "source": "The Hacker News"},
    {"url": "https://krebsonsecurity.com/feed/", "type": "article", "source": "Krebs on Security"},
    {"url": "https://isc.sans.edu/rssfeed.xml", "type": "article", "source": "SANS ISC"},
]

def fetch_media_sync():
    logger.info("Starting Media Hub sync via RSS...")
    db = SessionLocal()
    try:
        for src in SOURCES:
            try:
                feed = feedparser.parse(src["url"])
                # Limit to 15 entries per source to prevent DB bloat
                for entry in feed.entries[:15]:
                    title = entry.get("title", "")
                    url = entry.get("link", "")
                    
                    if not title or not url:
                        continue
                    
                    # Parse published date safely
                    published_at = datetime.utcnow()
                    if entry.get("published_parsed"):
                        published_at = datetime.fromtimestamp(time.mktime(entry.published_parsed))
                    
                    # Extract thumbnails
                    thumbnail_url = None
                    if "media_thumbnail" in entry and len(entry.media_thumbnail) > 0:
                        thumbnail_url = entry.media_thumbnail[0].get("url")
                    elif "media_content" in entry and len(entry.media_content) > 0:
                        thumbnail_url = entry.media_content[0].get("url")
                    elif "image" in entry and "href" in entry.image:
                        thumbnail_url = entry.image.href
                    elif hasattr(feed, "feed") and hasattr(feed.feed, "image") and hasattr(feed.feed.image, "href"):
                        thumbnail_url = feed.feed.image.href
                    
                    # Extract summary (clean HTML tags if necessary, but we'll store max 500 chars)
                    summary = entry.get("summary", "")
                    from bs4 import BeautifulSoup
                    text_desc = BeautifulSoup(summary, "html.parser").get_text()
                    description = text_desc[:500] + "..." if len(text_desc) > 500 else text_desc

                    # Skip duplicates based on URL
                    exists = db.query(MediaItem).filter(MediaItem.url == url).first()
                    if not exists:
                        item = MediaItem(
                            title=title,
                            description=description,
                            url=url,
                            thumbnail_url=thumbnail_url,
                            source_name=src["source"],
                            media_type=src["type"],
                            published_at=published_at
                        )
                        db.add(item)
            except Exception as e:
                logger.warning(f"Failed to fetch {src['source']}: {e}")
                
        db.commit()
        logger.info("Media Hub sync completed successfully.")
    except Exception as e:
        logger.error(f"Global media sync error: {e}")
        db.rollback()
    finally:
        db.close()
