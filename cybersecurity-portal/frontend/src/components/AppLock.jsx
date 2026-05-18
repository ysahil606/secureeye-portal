import { useState, useEffect } from 'react'
import { Lock, Shield, Delete, Check } from 'lucide-react'
import { Preferences } from '@capacitor/preferences'
import clsx from 'clsx'

export default function AppLock({ onSuccess }) {
  const [pin, setPin] = useState('')
  const [savedPin, setSavedPin] = useState(null)
  const [mode, setMode] = useState('verify') // 'verify' or 'setup'
  const [error, setError] = useState(false)

  useEffect(() => {
    checkPin()
  }, [])

  const checkPin = async () => {
    const { value } = await Preferences.get({ key: 'app_pin' })
    if (value) {
      setSavedPin(value)
      setMode('verify')
    } else {
      setMode('setup')
    }
  }

  const handleKeyPress = (num) => {
    if (pin.length < 4) {
      const newPin = pin + num
      setPin(newPin)
      setError(false)
      
      if (newPin.length === 4) {
        handleComplete(newPin)
      }
    }
  }

  const handleDelete = () => {
    setPin(pin.slice(0, -1))
  }

  const handleComplete = async (finalPin) => {
    if (mode === 'setup') {
      await Preferences.set({ key: 'app_pin', value: finalPin })
      setSavedPin(finalPin)
      onSuccess()
    } else {
      if (finalPin === savedPin) {
        onSuccess()
      } else {
        setError(true)
        setPin('')
        // Brief shake effect or haptics would go here
      }
    }
  }

  return (
    <div className="fixed inset-0 z-[100] bg-dark-900 flex flex-col items-center justify-center p-6">
      <div className="mb-12 text-center">
        <div className="w-20 h-20 bg-blue-600/20 rounded-full flex items-center justify-center mx-auto mb-4 border border-blue-500/30">
          <Lock className={clsx("w-10 h-10", error ? "text-red-500 animate-bounce" : "text-blue-400")} />
        </div>
        <h2 className="text-2xl font-bold text-white">
          {mode === 'setup' ? 'Set Secure PIN' : 'Enter App PIN'}
        </h2>
        <p className="text-slate-400 mt-2">
          {error ? 'Incorrect PIN, try again' : 'Access to SecureEye is restricted'}
        </p>
      </div>

      {/* PIN Dots */}
      <div className="flex gap-4 mb-16">
        {[1, 2, 3, 4].map((i) => (
          <div
            key={i}
            className={clsx(
              "w-4 h-4 rounded-full border-2 transition-all duration-200",
              pin.length >= i 
                ? "bg-blue-500 border-blue-500 scale-125" 
                : "border-dark-600 bg-dark-800"
            )}
          />
        ))}
      </div>

      {/* Numpad */}
      <div className="grid grid-cols-3 gap-6 w-full max-w-xs">
        {[1, 2, 3, 4, 5, 6, 7, 8, 9].map((num) => (
          <button
            key={num}
            onClick={() => handleKeyPress(num.toString())}
            className="w-full aspect-square rounded-full bg-dark-800 hover:bg-dark-700 border border-dark-600 text-2xl font-bold text-white flex items-center justify-center transition-colors active:scale-90"
          >
            {num}
          </button>
        ))}
        <div />
        <button
          onClick={() => handleKeyPress('0')}
          className="w-full aspect-square rounded-full bg-dark-800 hover:bg-dark-700 border border-dark-600 text-2xl font-bold text-white flex items-center justify-center transition-colors active:scale-90"
        >
          0
        </button>
        <button
          onClick={handleDelete}
          className="w-full aspect-square rounded-full flex items-center justify-center text-slate-500 hover:text-white transition-colors"
        >
          <Delete className="w-8 h-8" />
        </button>
      </div>

      <div className="mt-12 flex items-center gap-2 text-slate-500">
        <Shield className="w-4 h-4" />
        <span className="text-xs font-medium tracking-widest uppercase">AES-256 Encrypted Lock</span>
      </div>
    </div>
  )
}
