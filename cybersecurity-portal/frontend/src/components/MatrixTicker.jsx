import React, { useState, useEffect } from 'react'
import api from '../services/api'

export default function MatrixTicker() {
  const [tickerBytes, setTickerBytes] = useState([
    "[SYSTEM] MATRIX THREAT TICKER INITIALIZING...",
    "[SYSTEM] ESTABLISHING SECURE CONNECTION TO INTELLIGENCE FEEDS..."
  ])

  useEffect(() => {
    fetchTicker()
    // Refresh ticker every 5 minutes
    const interval = setInterval(fetchTicker, 300000)
    return () => clearInterval(interval)
  }, [])

  const fetchTicker = async () => {
    try {
      const res = await api.get('/ticker')
      if (res.data && res.data.ticker_bytes && res.data.ticker_bytes.length > 0) {
        setTickerBytes(res.data.ticker_bytes)
      }
    } catch (error) {
      console.error("Failed to fetch ticker:", error)
    }
  }

  // Combine all bytes into one long string separated by a cool separator
  const tickerText = tickerBytes.join("  |  ") + "  |  "

  return (
    <div className="fixed bottom-0 left-0 w-full bg-black border-t border-[#00FF41]/30 text-[#00FF41] font-mono text-sm py-1.5 z-50 overflow-hidden select-none" style={{ textShadow: "0 0 5px #00FF41" }}>
      <div className="flex whitespace-nowrap animate-ticker">
        {/* We duplicate the text multiple times so the infinite scroll animation is seamless */}
        <span className="inline-block px-4">{tickerText}</span>
        <span className="inline-block px-4">{tickerText}</span>
        <span className="inline-block px-4">{tickerText}</span>
        <span className="inline-block px-4">{tickerText}</span>
      </div>
      <style dangerouslySetInnerHTML={{__html: `
        @keyframes ticker {
          0% { transform: translateX(0); }
          100% { transform: translateX(-50%); }
        }
        .animate-ticker {
          animation: ticker 40s linear infinite;
        }
      `}} />
    </div>
  )
}
