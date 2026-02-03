import { useState, useEffect } from 'react'
import Dashboard from './components/Dashboard'
import { useMetrics } from './hooks/useMetrics'

type Theme = 'dark' | 'light'

function App() {
    const { metrics, drops, sessions, connected, error } = useMetrics()
    const [systemStatus, setSystemStatus] = useState<'online' | 'offline' | 'warning'>('offline')
    const [theme, setTheme] = useState<Theme>(() => {
        const saved = localStorage.getItem('theme')
        return (saved as Theme) || 'dark'
    })

    useEffect(() => {
        if (connected && !error) {
            setSystemStatus('online')
        } else if (error) {
            setSystemStatus('warning')
        } else {
            setSystemStatus('offline')
        }
    }, [connected, error])

    useEffect(() => {
        document.documentElement.classList.toggle('light', theme === 'light')
        localStorage.setItem('theme', theme)
    }, [theme])

    const toggleTheme = () => {
        setTheme(prev => prev === 'dark' ? 'light' : 'dark')
    }

    return (
        <div className={`min-h-screen transition-colors duration-300 ${theme === 'dark' ? 'bg-cndi-dark' : 'bg-gray-100'}`}>
            <header className={`border-b px-6 py-4 transition-colors duration-300 ${theme === 'dark' ? 'bg-slate-800/50 border-slate-700' : 'bg-white border-gray-200 shadow-sm'}`}>
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div>
                            <h1 className={`text-xl font-bold ${theme === 'dark' ? 'text-white' : 'text-gray-900'}`}>5G Observability Platform</h1>
                            <p className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-gray-500'}`}>Real-time Network Monitoring & Analytics</p>
                        </div>
                    </div>

                    <div className="flex items-center gap-6">
                        <div className="flex items-center gap-2">
                            <span className={`px-4 py-2 rounded-lg text-sm font-medium bg-blue-500 text-white shadow-lg shadow-blue-500/30`}>
                                Data Plane Monitor
                            </span>
                        </div>

                        <div className={`h-6 w-px ${theme === 'dark' ? 'bg-slate-600' : 'bg-gray-300'}`}></div>

                        <button
                            onClick={toggleTheme}
                            className={`p-2 rounded-lg transition-all ${theme === 'dark'
                                ? 'bg-slate-700 hover:bg-slate-600 text-yellow-400'
                                : 'bg-gray-200 hover:bg-gray-300 text-gray-700'
                                }`}
                            title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
                        >
                            {theme === 'dark' ? (
                                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                                    <path fillRule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" clipRule="evenodd" />
                                </svg>
                            ) : (
                                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                                    <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
                                </svg>
                            )}
                        </button>

                        <div className={`h-6 w-px ${theme === 'dark' ? 'bg-slate-600' : 'bg-gray-300'}`}></div>

                        <div className="flex items-center gap-2">
                            <div className={`w-3 h-3 rounded-full ${systemStatus === 'online' ? 'bg-green-500' :
                                systemStatus === 'warning' ? 'bg-yellow-500' : 'bg-red-500'
                                }`} />
                            <span className={`text-sm ${theme === 'dark' ? 'text-slate-300' : 'text-gray-600'}`}>
                                {systemStatus === 'online' ? 'System Online' :
                                    systemStatus === 'warning' ? 'Partial Connection' : 'Offline'}
                            </span>
                        </div>
                        <div className={`text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-gray-500'}`}>
                            {new Date().toLocaleTimeString()}
                        </div>
                    </div>
                </div>
            </header>

            <main className="p-6">
                {error && (
                    <div className={`mb-4 p-4 border rounded-lg ${theme === 'dark' ? 'bg-red-500/10 border-red-500/50 text-red-400' : 'bg-red-50 border-red-200 text-red-600'}`}>
                        ⚠️ Connection Error: {error}. Make sure the API server is running.
                    </div>
                )}

                <Dashboard
                    theme={theme}
                    metrics={metrics}
                    drops={drops}
                    sessions={sessions}
                />
            </main>

            <footer className={`fixed bottom-0 left-0 right-0 border-t px-6 py-2 transition-colors duration-300 ${theme === 'dark' ? 'bg-slate-800/50 border-slate-700' : 'bg-white border-gray-200'}`}>
                <div className={`flex items-center justify-between text-sm ${theme === 'dark' ? 'text-slate-400' : 'text-gray-500'}`}>
                    <span>Project Location: <a href='https://github.com/solar224/5G-DPOP'>5G-DPOP</a></span>
                    <span>WebSocket: {connected ? '🟢 Connected' : '🔴 Disconnected'}</span>
                </div>
            </footer>
        </div>
    )
}

export default App
