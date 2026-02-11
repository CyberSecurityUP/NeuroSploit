import { useState, useEffect } from 'react'
import { Save, Shield, Trash2, RefreshCw, AlertTriangle, Brain, Router, Eye } from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import Input from '../components/common/Input'

interface Settings {
  llm_provider: string
  has_anthropic_key: boolean
  has_openai_key: boolean
  has_openrouter_key: boolean
  max_concurrent_scans: number
  aggressive_mode: boolean
  default_scan_type: string
  recon_enabled_by_default: boolean
  enable_model_routing: boolean
  enable_knowledge_augmentation: boolean
  enable_browser_validation: boolean
  max_output_tokens: number | null
}

interface DbStats {
  scans: number
  vulnerabilities: number
  endpoints: number
  reports: number
}

export default function SettingsPage() {
  const [settings, setSettings] = useState<Settings | null>(null)
  const [dbStats, setDbStats] = useState<DbStats | null>(null)
  const [apiKey, setApiKey] = useState('')
  const [openaiKey, setOpenaiKey] = useState('')
  const [openrouterKey, setOpenrouterKey] = useState('')
  const [llmProvider, setLlmProvider] = useState('claude')
  const [maxConcurrentScans, setMaxConcurrentScans] = useState('3')
  const [maxOutputTokens, setMaxOutputTokens] = useState('')
  const [aggressiveMode, setAggressiveMode] = useState(false)
  const [enableModelRouting, setEnableModelRouting] = useState(false)
  const [enableKnowledgeAugmentation, setEnableKnowledgeAugmentation] = useState(false)
  const [enableBrowserValidation, setEnableBrowserValidation] = useState(false)
  const [isSaving, setIsSaving] = useState(false)
  const [isClearing, setIsClearing] = useState(false)
  const [showClearConfirm, setShowClearConfirm] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null)

  useEffect(() => {
    fetchSettings()
    fetchDbStats()
  }, [])

  const fetchSettings = async () => {
    try {
      const response = await fetch('/api/v1/settings')
      if (response.ok) {
        const data = await response.json()
        setSettings(data)
        setLlmProvider(data.llm_provider)
        setMaxConcurrentScans(String(data.max_concurrent_scans))
        setAggressiveMode(data.aggressive_mode)
        setEnableModelRouting(data.enable_model_routing ?? false)
        setEnableKnowledgeAugmentation(data.enable_knowledge_augmentation ?? false)
        setEnableBrowserValidation(data.enable_browser_validation ?? false)
        setMaxOutputTokens(data.max_output_tokens ? String(data.max_output_tokens) : '')
      }
    } catch (error) {
      console.error('Failed to fetch settings:', error)
    }
  }

  const fetchDbStats = async () => {
    try {
      const response = await fetch('/api/v1/settings/stats')
      if (response.ok) {
        const data = await response.json()
        setDbStats(data)
      }
    } catch (error) {
      console.error('Failed to fetch db stats:', error)
    }
  }

  const handleSave = async () => {
    setIsSaving(true)
    setMessage(null)

    try {
      const response = await fetch('/api/v1/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          llm_provider: llmProvider,
          anthropic_api_key: apiKey || undefined,
          openai_api_key: openaiKey || undefined,
          openrouter_api_key: openrouterKey || undefined,
          max_concurrent_scans: parseInt(maxConcurrentScans),
          aggressive_mode: aggressiveMode,
          enable_model_routing: enableModelRouting,
          enable_knowledge_augmentation: enableKnowledgeAugmentation,
          enable_browser_validation: enableBrowserValidation,
          max_output_tokens: maxOutputTokens ? parseInt(maxOutputTokens) : null
        })
      })

      if (response.ok) {
        const data = await response.json()
        setSettings(data)
        setApiKey('')
        setOpenaiKey('')
        setOpenrouterKey('')
        setMessage({ type: 'success', text: 'Settings saved successfully!' })
      } else {
        setMessage({ type: 'error', text: 'Failed to save settings' })
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'Failed to save settings' })
    } finally {
      setIsSaving(false)
    }
  }

  const handleClearDatabase = async () => {
    setIsClearing(true)
    setMessage(null)

    try {
      const response = await fetch('/api/v1/settings/clear-database', {
        method: 'POST'
      })

      if (response.ok) {
        setMessage({ type: 'success', text: 'Database cleared successfully!' })
        setShowClearConfirm(false)
        fetchDbStats()
      } else {
        const data = await response.json()
        setMessage({ type: 'error', text: data.detail || 'Failed to clear database' })
      }
    } catch (error) {
      setMessage({ type: 'error', text: 'Failed to clear database' })
    } finally {
      setIsClearing(false)
    }
  }

  const ToggleSwitch = ({ enabled, onToggle }: { enabled: boolean; onToggle: () => void }) => (
    <button
      onClick={onToggle}
      className={`w-12 h-6 rounded-full transition-colors ${enabled ? 'bg-primary-500' : 'bg-dark-700'}`}
    >
      <div className={`w-5 h-5 bg-white rounded-full shadow-md transform transition-transform ${enabled ? 'translate-x-6' : 'translate-x-0.5'}`} />
    </button>
  )

  return (
    <div className="max-w-2xl mx-auto space-y-6 animate-fadeIn">
      {/* Status Message */}
      {message && (
        <div className={`p-4 rounded-lg ${message.type === 'success' ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'}`}>
          {message.text}
        </div>
      )}

      {/* LLM Configuration */}
      <Card title="LLM Configuration" subtitle="Configure AI model for vulnerability analysis">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-dark-200 mb-2">
              LLM Provider
            </label>
            <div className="flex gap-2 flex-wrap">
              {['claude', 'openai', 'openrouter', 'ollama'].map((provider) => (
                <Button
                  key={provider}
                  variant={llmProvider === provider ? 'primary' : 'secondary'}
                  onClick={() => setLlmProvider(provider)}
                >
                  {provider === 'openrouter' ? 'OpenRouter' : provider.charAt(0).toUpperCase() + provider.slice(1)}
                </Button>
              ))}
            </div>
          </div>

          {llmProvider === 'claude' && (
            <Input
              label="Anthropic API Key"
              type="password"
              placeholder={settings?.has_anthropic_key ? '••••••••••••••••' : 'sk-ant-...'}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              helperText={settings?.has_anthropic_key ? 'API key is configured. Enter a new key to update.' : 'Required for Claude-powered analysis'}
            />
          )}

          {llmProvider === 'openai' && (
            <Input
              label="OpenAI API Key"
              type="password"
              placeholder={settings?.has_openai_key ? '••••••••••••••••' : 'sk-...'}
              value={openaiKey}
              onChange={(e) => setOpenaiKey(e.target.value)}
              helperText={settings?.has_openai_key ? 'API key is configured. Enter a new key to update.' : 'Required for OpenAI-powered analysis'}
            />
          )}

          {llmProvider === 'openrouter' && (
            <Input
              label="OpenRouter API Key"
              type="password"
              placeholder={settings?.has_openrouter_key ? '••••••••••••••••' : 'sk-or-...'}
              value={openrouterKey}
              onChange={(e) => setOpenrouterKey(e.target.value)}
              helperText={settings?.has_openrouter_key ? 'API key is configured. Enter a new key to update.' : 'Required for OpenRouter model access'}
            />
          )}

          <Input
            label="Max Output Tokens"
            type="number"
            min="1024"
            max="64000"
            placeholder="Default (profile-based)"
            value={maxOutputTokens}
            onChange={(e) => setMaxOutputTokens(e.target.value)}
            helperText="Override max output tokens (up to 64000 for Claude). Leave empty for profile defaults."
          />
        </div>
      </Card>

      {/* Advanced Features */}
      <Card title="Advanced Features" subtitle="Optional AI enhancement modules">
        <div className="space-y-3">
          <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg">
            <div className="flex items-center gap-3">
              <Router className="w-5 h-5 text-blue-400" />
              <div>
                <p className="font-medium text-white">Model Routing</p>
                <p className="text-sm text-dark-400">
                  Route tasks to specialized LLM profiles by type (reasoning, analysis, generation)
                </p>
              </div>
            </div>
            <ToggleSwitch enabled={enableModelRouting} onToggle={() => setEnableModelRouting(!enableModelRouting)} />
          </div>

          <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg">
            <div className="flex items-center gap-3">
              <Brain className="w-5 h-5 text-purple-400" />
              <div>
                <p className="font-medium text-white">Knowledge Augmentation</p>
                <p className="text-sm text-dark-400">
                  Enrich AI context with bug bounty pattern datasets (19 vuln types)
                </p>
              </div>
            </div>
            <ToggleSwitch enabled={enableKnowledgeAugmentation} onToggle={() => setEnableKnowledgeAugmentation(!enableKnowledgeAugmentation)} />
          </div>

          <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg">
            <div className="flex items-center gap-3">
              <Eye className="w-5 h-5 text-green-400" />
              <div>
                <p className="font-medium text-white">Browser Validation</p>
                <p className="text-sm text-dark-400">
                  Playwright-based browser validation with screenshot capture
                </p>
              </div>
            </div>
            <ToggleSwitch enabled={enableBrowserValidation} onToggle={() => setEnableBrowserValidation(!enableBrowserValidation)} />
          </div>
        </div>
      </Card>

      {/* Scan Settings */}
      <Card title="Scan Settings" subtitle="Configure default scan behavior">
        <div className="space-y-4">
          <Input
            label="Max Concurrent Scans"
            type="number"
            min="1"
            max="10"
            value={maxConcurrentScans}
            onChange={(e) => setMaxConcurrentScans(e.target.value)}
            helperText="Maximum number of scans that can run simultaneously"
          />

          <div className="flex items-center justify-between p-4 bg-dark-900/50 rounded-lg">
            <div>
              <p className="font-medium text-white">Enable Aggressive Mode</p>
              <p className="text-sm text-dark-400">
                Use more payloads and bypass techniques (may be slower)
              </p>
            </div>
            <ToggleSwitch enabled={aggressiveMode} onToggle={() => setAggressiveMode(!aggressiveMode)} />
          </div>
        </div>
      </Card>

      {/* Database Management */}
      <Card title="Database Management" subtitle="Manage stored data">
        <div className="space-y-4">
          {/* Stats */}
          {dbStats && (
            <div className="grid grid-cols-4 gap-4 p-4 bg-dark-900/50 rounded-lg">
              <div className="text-center">
                <p className="text-2xl font-bold text-white">{dbStats.scans}</p>
                <p className="text-xs text-dark-400">Scans</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-white">{dbStats.vulnerabilities}</p>
                <p className="text-xs text-dark-400">Vulnerabilities</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-white">{dbStats.endpoints}</p>
                <p className="text-xs text-dark-400">Endpoints</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-bold text-white">{dbStats.reports}</p>
                <p className="text-xs text-dark-400">Reports</p>
              </div>
            </div>
          )}

          {/* Clear Database */}
          {!showClearConfirm ? (
            <div className="flex items-center justify-between p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
              <div>
                <p className="font-medium text-white">Clear All Data</p>
                <p className="text-sm text-dark-400">
                  Remove all scans, vulnerabilities, and reports
                </p>
              </div>
              <Button variant="danger" onClick={() => setShowClearConfirm(true)}>
                <Trash2 className="w-4 h-4 mr-2" />
                Clear Database
              </Button>
            </div>
          ) : (
            <div className="p-4 bg-red-500/20 border border-red-500/50 rounded-lg space-y-4">
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-6 h-6 text-red-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="font-medium text-red-400">Are you sure?</p>
                  <p className="text-sm text-dark-300 mt-1">
                    This will permanently delete all scans, vulnerabilities, endpoints, and reports.
                    This action cannot be undone.
                  </p>
                </div>
              </div>
              <div className="flex gap-3 justify-end">
                <Button variant="secondary" onClick={() => setShowClearConfirm(false)}>
                  Cancel
                </Button>
                <Button variant="danger" onClick={handleClearDatabase} isLoading={isClearing}>
                  <Trash2 className="w-4 h-4 mr-2" />
                  Yes, Clear Everything
                </Button>
              </div>
            </div>
          )}

          {/* Refresh Stats */}
          <Button variant="secondary" onClick={fetchDbStats} className="w-full">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh Statistics
          </Button>
        </div>
      </Card>

      {/* About */}
      <Card title="About NeuroSploit">
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-primary-500" />
            <div>
              <p className="font-bold text-white text-lg">NeuroSploit v3.0</p>
              <p className="text-sm text-dark-400">AI-Powered Penetration Testing Platform</p>
            </div>
          </div>
          <div className="text-sm text-dark-400 space-y-1">
            <p>Dynamic vulnerability testing driven by AI prompts</p>
            <p>50+ vulnerability types across 10 categories</p>
            <p>Multi-provider LLM support (Claude, GPT, OpenRouter, Ollama)</p>
            <p>Task-type model routing and knowledge augmentation</p>
            <p>Playwright browser validation with screenshot capture</p>
            <p>OHVR-structured PoC reporting</p>
            <p>Scheduled recurring scans with cron/interval triggers</p>
          </div>
        </div>
      </Card>

      {/* Save Button */}
      <div className="flex justify-end">
        <Button onClick={handleSave} isLoading={isSaving} size="lg">
          <Save className="w-5 h-5 mr-2" />
          Save Settings
        </Button>
      </div>
    </div>
  )
}
