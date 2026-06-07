import { useState } from 'react'
import { NavLink, useNavigate, useLocation } from 'react-router-dom'
import {
  Shield, LayoutDashboard, FileText, Search,
  Bell, Users, Layers, Cpu, Clock, Bug,
  Network, LogOut, ChevronRight, Sparkles, X, Ghost, LifeBuoy, BrainCircuit, Settings as SettingsIcon, Tv, Globe,
  ChevronDown, Flame, Fish
} from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { useAuth } from '../context/AuthContext'
import clsx from 'clsx'

const NAVIGATION_GROUPS = [
  {
    title: 'Overview',
    items: [
      { to: '/dashboard', icon: LayoutDashboard, label: 'Dashboard', feature: 'dashboard' },
    ]
  },
  {
    title: 'Threat Intelligence',
    items: [
      { to: '/advisories', icon: FileText, label: 'Advisories', feature: 'advisories' },
      { to: '/search', icon: Search, label: 'Smart Search', feature: 'search' },
      { to: '/timeline', icon: Clock, label: 'Threat Timeline', feature: 'timeline' },
      { to: '/zero-days', icon: Bug, label: 'Zero-Day Tracker', feature: 'zero-days' },
      { to: '/phishing', icon: Fish, label: 'Phishing Monitor', feature: 'advisories' },
    ]
  },
  {
    title: 'Integrations & Monitoring',
    items: [
      { to: '/misp', icon: Shield, label: 'MISP Integration', feature: 'misp' },
      { to: '/iocs', icon: Network, label: 'IOC Management', feature: 'iocs' },
      { to: '/darkweb', icon: Ghost, label: 'Dark Web Monitor', feature: 'darkweb' },
      { to: '/media', icon: Tv, label: 'Media Hub', feature: 'media' },
    ]
  },
  {
    title: 'Analysis & Labs',
    items: [
      { to: '/deepscan', icon: Cpu, label: 'DeepScan Lab', feature: 'deepscan' },
      { to: '/cyber-weather', icon: Globe, label: 'Cyber Weather', feature: 'dashboard' },
      { to: '/advanced', icon: Sparkles, label: 'Advanced Center', feature: 'advanced' },
    ]
  },
  {
    title: 'Administration',
    items: [
      { to: '/admin/users', icon: Users, label: 'User Management', feature: 'admin_users' },
      { to: '/admin/sectors', icon: Layers, label: 'Manage Sectors', feature: 'admin_sectors' },
      { to: '/admin/feeds', icon: Cpu, label: 'Feed Logs', feature: 'admin_feeds' },
      { to: '/admin/permissions', icon: Shield, label: 'Role Permissions', feature: 'admin_permissions' },
      { to: '/settings', icon: SettingsIcon, label: 'Settings', feature: 'settings' },
    ]
  }
]

export default function Sidebar({ collapsed, setCollapsed, mobileOpen = false, onMobileClose = () => {} }) {
  const { user, logout, hasFeatureAccess } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  
  // Track expanded groups. By default, open the group containing the active link, or just default open everything.
  // For a clean look, let's open all of them by default.
  const [expandedGroups, setExpandedGroups] = useState(
    NAVIGATION_GROUPS.reduce((acc, group) => {
      acc[group.title] = true;
      return acc;
    }, {})
  )

  const toggleGroup = (title) => {
    if (collapsed) return; // Prevent toggling when sidebar is collapsed
    setExpandedGroups(prev => ({
      ...prev,
      [title]: !prev[title]
    }))
  }

  const handleLogout = () => {
    logout()
    onMobileClose()
    navigate('/login')
  }

  const renderNavItems = () => {
    return NAVIGATION_GROUPS.map((group, groupIdx) => {
      // Filter out items the user doesn't have access to
      const visibleItems = group.items.filter(item => hasFeatureAccess(item.feature))
      
      // If no items in this group are visible, skip rendering the group
      if (visibleItems.length === 0) return null

      const isExpanded = expandedGroups[group.title]

      return (
        <div key={group.title} className={clsx("mb-8", collapsed && "mb-8")}>
          {/* Group Header */}
          <button
            onClick={() => toggleGroup(group.title)}
            className={clsx(
              "flex items-center justify-between w-full px-4 py-2 transition-colors duration-200 group",
              collapsed ? "justify-center" : "text-left"
            )}
          >
            {!collapsed && (
              <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider group-hover:text-slate-300 transition-colors">
                {group.title}
              </span>
            )}
            {collapsed ? (
              <div className="w-8 h-1 rounded-full bg-slate-800" />
            ) : (
              <motion.div
                animate={{ rotate: isExpanded ? 0 : -90 }}
                transition={{ type: 'spring', stiffness: 200, damping: 15 }}
              >
                <ChevronDown className="w-3.5 h-3.5 text-slate-500" />
              </motion.div>
            )}
          </button>

          {/* Group Items */}
          <AnimatePresence initial={false}>
            {(isExpanded || collapsed) && (
              <motion.div
                initial="collapsed"
                animate="expanded"
                exit="collapsed"
                variants={{
                  expanded: { opacity: 1, height: 'auto', transition: { staggerChildren: 0.05, delayChildren: 0.1 } },
                  collapsed: { opacity: 0, height: 0, transition: { staggerChildren: 0.02, staggerDirection: -1 } }
                }}
                className="overflow-hidden"
              >
                <div className="space-y-1">
                  {visibleItems.map((item, i) => {
                    const isActive = location.pathname === item.to
                    
                    return (
                      <motion.div
                        key={item.to}
                        variants={{
                          expanded: { opacity: 1, x: 0, transition: { type: 'spring', stiffness: 300, damping: 20 } },
                          collapsed: { opacity: 0, x: -20, transition: { duration: 0.2 } }
                        }}
                      >
                        <NavLink to={item.to}
                          onClick={onMobileClose}
                          className={clsx(
                      'relative flex items-center gap-4 px-4 py-2.5 rounded-2xl text-[13px] transition-all duration-500 group overflow-hidden',
                      isActive
                        ? 'bg-dark-900/60 text-white border border-cyan-500/30 shadow-[0_0_20px_rgba(6,182,212,0.15)]'
                        : 'text-slate-400 hover:text-white border border-transparent hover:border-white/5'
                    )}>
                    
                    {/* Active Indicator & Hover Backgrounds */}
                    <div className={clsx(
                      "absolute inset-0 bg-gradient-to-r from-cyan-500/10 to-blue-500/5 transition-opacity duration-500",
                      isActive ? "opacity-100" : "opacity-0 group-hover:opacity-100"
                    )} />
                    <div className={clsx(
                      "absolute left-0 top-0 bottom-0 w-1 rounded-r-full transition-all duration-500 ease-out",
                      isActive ? "bg-cyan-400 shadow-[0_0_15px_rgba(34,211,238,1)]" : "bg-transparent group-hover:bg-cyan-500/50"
                    )} />
                    
                    {/* Icon Container */}
                    <div className={clsx(
                      "relative flex items-center justify-center w-8 h-8 rounded-xl transition-all duration-500",
                      isActive ? "bg-cyan-500/20 shadow-[inset_0_0_10px_rgba(34,211,238,0.3)]" : "bg-dark-800/50 group-hover:bg-dark-700/50 group-hover:scale-110 group-hover:shadow-[0_0_15px_rgba(255,255,255,0.05)]"
                    )}>
                      <item.icon className={clsx(
                        "w-4 h-4 flex-shrink-0 transition-all duration-500", 
                        isActive ? "text-cyan-300 drop-shadow-[0_0_8px_rgba(34,211,238,0.8)]" : "text-slate-500 group-hover:text-cyan-300"
                      )} />
                    </div>
                    
                    {/* Label */}
                    {!collapsed && (
                      <span className={clsx(
                        "font-bold truncate tracking-wide transition-all duration-500 relative z-10",
                        isActive ? "text-transparent bg-clip-text bg-gradient-to-r from-white to-cyan-100 drop-shadow-sm" : "group-hover:translate-x-1"
                      )}>
                        {item.label}
                      </span>
                    )}
                      </NavLink>
                      </motion.div>
                    )
                  })}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )
    })
  }

  const renderSidebarContent = (isMobile = false) => (
    <>
      <div className="flex items-center gap-3 px-4 py-5 border-b border-white/5 min-h-[70px]">
        <div className="w-9 h-9 bg-gradient-to-br from-blue-600 to-purple-600 rounded-xl flex items-center justify-center flex-shrink-0 shadow-lg shadow-purple-500/20">
          <Shield className="w-5 h-5 text-white" />
        </div>
        {!collapsed && (
          <div className="overflow-hidden">
            <div className="font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-400 text-base leading-tight tracking-wide">SECURE_EYE</div>
            <div className="text-[10px] text-slate-500 uppercase tracking-widest">Advisory Portal</div>
          </div>
        )}
        {!isMobile && (
          <button
            onClick={() => setCollapsed(v => !v)}
            className="ml-auto hidden text-slate-500 hover:text-white transition-colors flex-shrink-0 md:block"
          >
            <ChevronRight className={clsx('w-4 h-4 transition-transform', collapsed ? '' : 'rotate-180')} />
          </button>
        )}
        {isMobile && (
          <button
            type="button"
            onClick={onMobileClose}
            className="ml-auto p-1.5 text-slate-500 hover:text-white"
            aria-label="Close navigation"
          >
            <X className="h-4 w-4" />
          </button>
        )}
      </div>

      <nav className="flex-1 overflow-y-auto py-4 px-2 space-y-1 scrollbar-hide">
        {renderNavItems()}
      </nav>

      <div className="border-t border-dark-600 p-3">
        <div className={clsx('flex items-center gap-3', collapsed && !isMobile && 'justify-center')}>
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
    </>
  )

  return (
    <>
      <aside className={clsx(
        'hidden lg:fixed lg:left-0 lg:top-0 lg:z-30 lg:flex lg:h-screen lg:flex-col lg:border-r lg:border-white/5 lg:bg-dark-900/40 lg:backdrop-blur-xl lg:transition-all lg:duration-300 shadow-2xl',
        collapsed ? 'lg:w-20' : 'lg:w-64'
      )}>
        {renderSidebarContent()}
      </aside>

      {mobileOpen && (
        <aside className="fixed left-0 top-0 z-50 flex h-screen w-72 max-w-[85vw] flex-col border-r border-white/5 bg-dark-900/80 backdrop-blur-xl shadow-2xl">
          {renderSidebarContent(true)}
        </aside>
      )}
    </>
  )
}
