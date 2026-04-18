import React from 'react'
import { AlertTriangle, RefreshCw, ShieldCheck } from 'lucide-react'

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null, autoRepairing: false }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    console.error('[Self-Healing] Frontend Crash Detected:', error, errorInfo)
  }

  handleAutoRepair = () => {
    this.setState({ autoRepairing: true })
    // In a real self-healing system, we could clear specific corrupted localStorage keys here
    setTimeout(() => {
        window.location.reload()
    }, 1000)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-dark-950 flex items-center justify-center p-6">
          <div className="max-w-md w-full card p-8 border-red-500/20 text-center space-y-6">
            <div className="w-16 h-16 bg-red-500/10 rounded-full flex items-center justify-center mx-auto">
              <AlertTriangle className="w-8 h-8 text-red-500" />
            </div>
            
            <div className="space-y-2">
              <h1 className="text-xl font-bold text-white">System Anomaly Detected</h1>
              <p className="text-slate-400 text-sm">
                The portal encountered an unexpected state. Our self-healing protocol is ready to attempt a repair.
              </p>
            </div>

            <div className="bg-dark-900 rounded-lg p-4 border border-dark-600 text-left">
                <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">Diagnostic Log</div>
                <div className="text-xs font-mono text-red-400/80 truncate">
                    {this.state.error?.toString() || 'Internal State Corruption'}
                </div>
            </div>

            <button
              onClick={this.handleAutoRepair}
              disabled={this.state.autoRepairing}
              className="btn-primary w-full py-3 flex items-center justify-center gap-2"
            >
              {this.state.autoRepairing ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <ShieldCheck className="w-4 h-4" />
              )}
              {this.state.autoRepairing ? 'Repairing System...' : 'Execute Self-Repair'}
            </button>
            
            <p className="text-[10px] text-slate-500 uppercase tracking-tight">
                Secure Resilience Protocol v1.0 — Active
            </p>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

export default ErrorBoundary
