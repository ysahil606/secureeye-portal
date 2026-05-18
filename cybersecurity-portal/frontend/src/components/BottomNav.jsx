import { NavLink } from 'react-router-dom'
import { LayoutDashboard, FileText, Search, BrainCircuit, Menu } from 'lucide-react'
import clsx from 'clsx'

const bottomNavItems = [
  { to: '/dashboard', icon: LayoutDashboard, label: 'Home' },
  { to: '/advisories', icon: FileText, label: 'Feed' },
  { to: '/search', icon: Search, label: 'Search' },
  { to: '/advanced-ops', icon: BrainCircuit, label: 'Ops' },
]

export default function BottomNav({ onMenuClick }) {
  return (
    <nav className="fixed bottom-0 inset-x-0 z-40 h-16 bg-dark-800 border-t border-dark-600 flex items-center justify-around px-2 lg:hidden safe-area-bottom">
      {bottomNavItems.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          className={({ isActive }) => clsx(
            'flex flex-col items-center justify-center gap-1 w-16 transition-colors',
            isActive ? 'text-blue-400' : 'text-slate-500 hover:text-slate-300'
          )}
        >
          <item.icon className="w-5 h-5" />
          <span className="text-[10px] font-medium tracking-tight">{item.label}</span>
        </NavLink>
      ))}
      <button
        onClick={onMenuClick}
        className="flex flex-col items-center justify-center gap-1 w-16 text-slate-500 hover:text-slate-300 transition-colors"
      >
        <Menu className="w-5 h-5" />
        <span className="text-[10px] font-medium tracking-tight">More</span>
      </button>
    </nav>
  )
}
