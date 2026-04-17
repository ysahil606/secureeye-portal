import { NavLink, useNavigate } from 'react-router-dom'
import {
  Shield, LayoutDashboard, FileText, Search, BarChart2,
  Bell, Settings, Users, Layers, Cpu, Clock, Bug,
  Network, LogOut, ChevronRight, AlertTriangle, Database
} from 'lucide-react'
import { useAuth } from '../context/AuthContext'
import clsx from 'clsx'

const navItems = [
  { to: '/dashboard',   icon: LayoutDashboard, label: 'Dashboard',       roles: ['admin','analyst','viewer'] },
  { to: '/advisories',  icon: FileText,         label: 'Advisories',      roles: ['admin','analyst','viewer'] },
  { to: '/search',      icon: Search,           label: 'Smart Search',    roles: ['admin','analyst','viewer'] },
  { to: '/timeline',    icon: Clock,            label: 'Threat Timeline', roles: ['admin','analyst','viewer'] },
  { to: '/zero-days',   icon: Bug,              label: 'Zero-Day Tracker',roles: ['admin','analyst','viewer'] },
  { to: '/iocs',        icon: Network,          label: 'IOC Management',  roles: ['admin','analyst','viewer'] },
  { to: '/alerts',      icon: Bell,             label: 'Alert Logs',      roles: ['admin','analyst'] },
  { separator: true },
  { to: '/admin/users', icon: Users,            label: 'User Management', roles: ['admin'] },
  { to: '/admin/sectors',icon: Layers,          label: 'Manage Sectors',  roles: ['admin'] },
  { to: '/admin/feeds', icon: Cpu,              label: 'Feed Logs',       roles: ['admin','analyst','viewer'] },
]

export default function Sidebar({ collapsed, setCollapsed }) {
  const { user, logout, isAdmin, isAnalyst } = useAuth()
  const navigate = useNavigate()

  const hasRole = (roles) => {
    if (!user) return false
    return roles.includes(user.role)
  }

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <aside className={clsx(
      'flex flex-col h-screen bg-dark-800 border-r border-dark-600 transition-all duration-300 fixed left-0 top-0 z-30',
      collapsed ? 'w-16' : 'w-60'
    )}>
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-4 border-b border-dark-600 min-h-[60px]">
        <div className="w-8 h-8 bg-blue-600/20 border border-blue-500/40 rounded-lg flex items-center justify-center flex-shrink-0">
          <Shield className="w-4 h-4 text-blue-400" />
        </div>
        {!collapsed && (
          <div className="overflow-hidden">
            <div className="font-bold text-white text-sm leading-tight">SecureEye</div>
            <div className="text-xs text-slate-500">Advisory Portal</div>
          </div>
        )}
        <button
          onClick={() => setCollapsed(v => !v)}
          className="ml-auto text-slate-500 hover:text-white transition-colors flex-shrink-0">
          <ChevronRight className={clsx('w-4 h-4 transition-transform', collapsed ? '' : 'rotate-180')} />
        </button>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-0.5">
        {navItems.map((item, i) => {
          if (item.separator) return (
            <div key={i} className="my-2 border-t border-dark-600" />
          )
          if (!hasRole(item.roles)) return null
          return (
            <NavLink key={item.to} to={item.to}
              className={({ isActive }) => clsx(
                'flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-all group',
                isActive
                  ? 'bg-blue-600/20 text-blue-300 border border-blue-500/30'
                  : 'text-slate-400 hover:text-white hover:bg-dark-700'
              )}>
              <item.icon className="w-4 h-4 flex-shrink-0" />
              {!collapsed && <span className="truncate">{item.label}</span>}
            </NavLink>
          )
        })}
      </nav>

      {/* User footer */}
      <div className="border-t border-dark-600 p-3">
        <div className={clsx('flex items-center gap-3', collapsed && 'justify-center')}>
          <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center flex-shrink-0 text-xs font-bold text-white uppercase">
            {user?.username?.[0] || 'U'}
          </div>
          {!collapsed && (
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-white truncate">{user?.full_name || user?.username}</div>
              <div className="text-xs text-slate-500 capitalize">{user?.role}</div>
            </div>
          )}
          {!collapsed && (
            <button onClick={handleLogout} className="text-slate-500 hover:text-red-400 transition-colors" title="Logout">
              <LogOut className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>
    </aside>
  )
}
