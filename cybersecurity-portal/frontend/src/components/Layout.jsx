import { useState } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import AIBotPopup from './AIBotPopup'
import clsx from 'clsx'

export default function Layout() {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <div className="flex min-h-screen bg-dark-900">
      <Sidebar collapsed={collapsed} setCollapsed={setCollapsed} />
      <main className={clsx('flex-1 transition-all duration-300 min-h-screen', collapsed ? 'ml-16' : 'ml-60')}>
        <div className="p-6 max-w-[1400px]">
          <Outlet />
        </div>
      </main>
      <AIBotPopup />
    </div>
  )
}
