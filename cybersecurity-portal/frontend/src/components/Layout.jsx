import { useState } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import BottomNav from './BottomNav'
import AIBotPopup from './AIBotPopup'
import clsx from 'clsx'
import { Shield } from 'lucide-react'

export default function Layout() {
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <div className="flex min-h-screen flex-col bg-dark-900 lg:flex-row">
      {/* Top Mobile Bar - Simplified */}
      <div className="flex h-14 items-center justify-center border-b border-dark-600 bg-dark-800 px-4 md:hidden">
        <div className="flex items-center gap-2 text-sm font-bold text-white">
          <Shield className="h-4 w-4 text-blue-400" />
          SecureEye Portal
        </div>
      </div>

      {mobileOpen && (
        <button
          type="button"
          className="fixed inset-0 z-40 bg-black/60 md:hidden"
          onClick={() => setMobileOpen(false)}
          aria-label="Close navigation overlay"
        />
      )}

      <Sidebar
        collapsed={collapsed}
        setCollapsed={setCollapsed}
        mobileOpen={mobileOpen}
        onMobileClose={() => setMobileOpen(false)}
      />

      <main className={clsx(
        'min-h-screen flex-1 transition-all duration-300 pb-16 lg:pb-0', 
        collapsed ? 'lg:ml-16' : 'lg:ml-60'
      )}>
        <div className="w-full max-w-[1400px] p-4 sm:p-5 md:p-6">
          <Outlet />
        </div>
      </main>

      <BottomNav onMenuClick={() => setMobileOpen(true)} />
      <AIBotPopup />
    </div>
  )
}
