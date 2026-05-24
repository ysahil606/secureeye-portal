import React, { useState, useEffect } from 'react'
import api from '../services/api'
import { Play, Headphones, Newspaper, ExternalLink, X, Loader2, Search as SearchIcon, Filter, Radio } from 'lucide-react'
import clsx from 'clsx'

export default function MediaHub() {
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [activeVideo, setActiveVideo] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedSource, setSelectedSource] = useState('All')
  const [activeTwitchChannel, setActiveTwitchChannel] = useState('hackthebox')

  const twitchChannels = [
    { id: 'hackthebox', name: 'HackTheBox (HTB)' },
    { id: 'piratesoftware', name: 'PirateSoftware' },
    { id: 'johnhammond', name: 'John Hammond' },
    { id: 'thecybermentor', name: 'The Cyber Mentor' }
  ]

  useEffect(() => {
    fetchMedia()
  }, [])

  const fetchMedia = async () => {
    try {
      const res = await api.get('/media')
      setItems(res.data)
    } catch (err) {
      setError('Failed to load media hub. The backend scraper may still be initializing.')
    } finally {
      setLoading(false)
    }
  }

  const getYoutubeId = (url) => {
    const match = url.match(/[?&]v=([^&]+)/)
    return match ? match[1] : null
  }

  const handleCardClick = (item) => {
    if (item.media_type === 'video') {
      const yId = getYoutubeId(item.url)
      if (yId) setActiveVideo(yId)
      else window.open(item.url, '_blank')
    } else {
      window.open(item.url, '_blank')
    }
  }

  if (loading) return (
    <div className="flex items-center justify-center h-full text-text-muted">
      <Loader2 className="w-8 h-8 animate-spin text-accent-primary" />
    </div>
  )

  if (error) return (
    <div className="p-8">
      <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-xl">
        {error}
      </div>
    </div>
  )

  const uniqueSources = ['All', ...new Set(items.map(i => i.source_name))].sort()

  const filteredItems = items.filter(item => {
    const matchesSearch = item.title.toLowerCase().includes(searchQuery.toLowerCase()) || 
                          (item.description && item.description.toLowerCase().includes(searchQuery.toLowerCase()))
    const matchesSource = selectedSource === 'All' || item.source_name === selectedSource
    return matchesSearch && matchesSource
  })

  const videos = filteredItems.filter(i => i.media_type === 'video')
  const podcasts = filteredItems.filter(i => i.media_type === 'podcast')
  const articles = filteredItems.filter(i => i.media_type === 'article')

  // Keep hero item stable regardless of search
  const allVideos = items.filter(i => i.media_type === 'video')
  const heroItem = allVideos.length > 0 ? allVideos[0] : null

  const ImageWithFallback = ({ src, alt, Icon }) => {
    const [error, setError] = useState(false)
    if (!src || error) {
      return (
        <div className="w-full h-full flex items-center justify-center bg-dark-800">
          <Icon className="w-12 h-12 text-dark-500" />
        </div>
      )
    }
    return (
      <img 
        src={src} 
        alt={alt} 
        onError={() => setError(true)}
        className="w-full h-full object-cover opacity-80 group-hover:opacity-100 transition-opacity" 
      />
    )
  }

  const Carousel = ({ title, data, icon: Icon }) => {
    if (!data || data.length === 0) return null
    return (
      <div className="mb-10 relative">
        <h2 className="text-xl font-bold text-text-primary mb-4 flex items-center gap-2 px-6">
          <Icon className="w-5 h-5 text-accent-primary" />
          {title}
        </h2>
        <div className="flex overflow-x-auto gap-4 px-6 pb-6 pt-2 scrollbar-hide snap-x" style={{ scrollbarWidth: 'none' }}>
          {data.map(item => (
            <div 
              key={item.id} 
              onClick={() => handleCardClick(item)}
              className="flex-none w-72 md:w-80 group cursor-pointer snap-start"
            >
              <div className="relative rounded-xl overflow-hidden aspect-video bg-bg-panel border border-border-light group-hover:border-accent-primary/50 transition-all duration-300 group-hover:-translate-y-2 group-hover:shadow-[0_10px_20px_rgba(0,0,0,0.3)]">
                <ImageWithFallback src={item.thumbnail_url} alt={item.title} Icon={Icon} />
                
                {/* Play Overlay for Videos */}
                {item.media_type === 'video' && (
                  <div className="absolute inset-0 flex items-center justify-center bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity">
                    <div className="w-12 h-12 bg-accent-primary rounded-full flex items-center justify-center pl-1 shadow-lg shadow-accent-primary/30">
                      <Play className="w-5 h-5 text-dark-950" />
                    </div>
                  </div>
                )}
                
                {/* External Link Overlay for others */}
                {item.media_type !== 'video' && (
                  <div className="absolute inset-0 flex items-center justify-center bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity">
                    <div className="bg-dark-800/90 text-white px-4 py-2 rounded-full font-medium flex items-center gap-2 backdrop-blur-sm border border-border-light">
                      <ExternalLink className="w-4 h-4" /> Open
                    </div>
                  </div>
                )}
              </div>
              <div className="mt-3 px-1">
                <p className="text-xs font-bold text-accent-primary uppercase tracking-wider mb-1">{item.source_name}</p>
                <h3 className="text-sm font-semibold text-text-primary line-clamp-2 group-hover:text-accent-primary transition-colors">{item.title}</h3>
                <p className="text-xs text-text-muted mt-1">{new Date(item.published_at).toLocaleDateString()}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-bg-base pb-20 overflow-x-hidden">
      {/* Hero Section */}
      {heroItem && (
        <div className="relative w-full h-[60vh] md:h-[70vh] mb-12 flex items-end">
          <div className="absolute inset-0">
            {heroItem.thumbnail_url ? (
              <img src={heroItem.thumbnail_url} className="w-full h-full object-cover" alt="Hero" />
            ) : (
              <div className="w-full h-full bg-dark-800" />
            )}
            <div className="absolute inset-0 bg-gradient-to-t from-bg-base via-bg-base/80 to-transparent" />
            <div className="absolute inset-0 bg-gradient-to-r from-bg-base via-bg-base/40 to-transparent" />
          </div>
          
          <div className="relative z-10 p-8 md:p-16 max-w-4xl">
            <span className="px-3 py-1 bg-accent-primary text-dark-950 font-bold text-xs uppercase tracking-widest rounded-sm mb-4 inline-block">
              Latest from {heroItem.source_name}
            </span>
            <h1 className="text-4xl md:text-6xl font-black text-white mb-4 leading-tight">
              {heroItem.title}
            </h1>
            <p className="text-lg text-gray-300 line-clamp-3 mb-8 max-w-2xl">
              {heroItem.description}
            </p>
            <div className="flex gap-4">
              <button 
                onClick={() => handleCardClick(heroItem)}
                className="flex items-center gap-2 bg-white text-black px-8 py-3 rounded-md font-bold hover:bg-gray-200 transition-colors"
              >
                <Play className="w-6 h-6 fill-black" />
                Play Now
              </button>
              <button 
                onClick={() => window.open(heroItem.url, '_blank')}
                className="flex items-center gap-2 bg-dark-600/80 text-white px-8 py-3 rounded-md font-bold hover:bg-dark-500 transition-colors backdrop-blur-sm"
              >
                <ExternalLink className="w-6 h-6" />
                View Source
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Live Twitch Streams */}
      <div className="mb-16 relative px-6 max-w-7xl mx-auto">
        <h2 className="text-xl font-bold text-text-primary mb-6 flex items-center gap-2">
          <Radio className="w-5 h-5 text-red-500 animate-pulse" />
          Live Hacker Streams
        </h2>
        
        <div className="flex flex-col lg:flex-row gap-6">
          <div className="flex-1 aspect-video bg-black rounded-2xl overflow-hidden shadow-2xl border border-border-light/20 relative">
            <iframe
              src={`https://player.twitch.tv/?channel=${activeTwitchChannel}&parent=${window.location.hostname || 'localhost'}&parent=secure-portal.vercel.app`}
              frameBorder="0"
              allowFullScreen
              scrolling="no"
              className="absolute inset-0 w-full h-full"
            ></iframe>
          </div>
          <div className="w-full lg:w-72 flex flex-col gap-3">
            <h3 className="text-sm font-bold text-text-muted uppercase tracking-wider mb-2">Popular Channels</h3>
            {twitchChannels.map(channel => (
              <button
                key={channel.id}
                onClick={() => setActiveTwitchChannel(channel.id)}
                className={clsx(
                  "flex items-center justify-between p-4 rounded-xl border transition-all text-left",
                  activeTwitchChannel === channel.id 
                    ? "bg-accent-primary/10 border-accent-primary text-white shadow-[0_0_15px_rgba(6,182,212,0.1)]"
                    : "bg-bg-panel border-border-light text-text-muted hover:border-text-muted hover:text-white"
                )}
              >
                <span className="font-semibold">{channel.name}</span>
                {activeTwitchChannel === channel.id && <Radio className="w-4 h-4 text-red-500 animate-pulse" />}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Search & Filters */}
      <div className="max-w-7xl mx-auto px-6 mb-12">
        <div className="flex flex-col md:flex-row gap-4 bg-bg-panel p-4 rounded-2xl border border-border-light shadow-lg">
          <div className="flex-1 relative">
            <SearchIcon className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-text-muted" />
            <input 
              type="text" 
              placeholder="Search videos, podcasts, and articles..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-dark-800 border border-border-light rounded-xl pl-12 pr-4 py-3 text-text-primary focus:outline-none focus:border-accent-primary transition-colors"
            />
          </div>
          <div className="w-full md:w-64 relative">
            <Filter className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-text-muted" />
            <select
              value={selectedSource}
              onChange={(e) => setSelectedSource(e.target.value)}
              className="w-full bg-dark-800 border border-border-light rounded-xl pl-12 pr-4 py-3 text-text-primary focus:outline-none focus:border-accent-primary transition-colors appearance-none cursor-pointer"
            >
              {uniqueSources.map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Carousels */}
      <Carousel title="Trending Cyber Videos" data={videos} icon={Play} />
      <Carousel title="Top Security Podcasts" data={podcasts} icon={Headphones} />
      <Carousel title="Latest News & Breaches" data={articles} icon={Newspaper} />

      {/* Video Modal */}
      {activeVideo && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/90 p-4 md:p-12 backdrop-blur-sm">
          <button 
            onClick={() => setActiveVideo(null)}
            className="absolute top-6 right-6 text-white hover:text-accent-primary transition-colors bg-dark-800/50 p-2 rounded-full"
          >
            <X className="w-8 h-8" />
          </button>
          <div className="w-full max-w-6xl aspect-video bg-black rounded-2xl overflow-hidden shadow-2xl border border-border-light/20">
            <iframe 
              className="w-full h-full"
              src={`https://www.youtube.com/embed/${activeVideo}?autoplay=1`} 
              title="YouTube video player" 
              frameBorder="0" 
              allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" 
              allowFullScreen
            ></iframe>
          </div>
        </div>
      )}
    </div>
  )
}
