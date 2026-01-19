import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  BookOpen, Plus, Trash2, Play, Search, Tag, Zap, X, Save
} from 'lucide-react'
import Card from '../components/common/Card'
import Button from '../components/common/Button'
import Input from '../components/common/Input'
import Textarea from '../components/common/Textarea'
import { agentApi } from '../services/api'
import type { AgentTask } from '../types'

const CATEGORIES = [
  { id: 'all', name: 'All Tasks', color: 'dark' },
  { id: 'full_auto', name: 'Full Auto', color: 'primary' },
  { id: 'recon', name: 'Reconnaissance', color: 'blue' },
  { id: 'vulnerability', name: 'Vulnerability', color: 'orange' },
  { id: 'custom', name: 'Custom', color: 'purple' },
  { id: 'reporting', name: 'Reporting', color: 'green' }
]

export default function TaskLibraryPage() {
  const navigate = useNavigate()

  const [tasks, setTasks] = useState<AgentTask[]>([])
  const [filteredTasks, setFilteredTasks] = useState<AgentTask[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedTask, setSelectedTask] = useState<AgentTask | null>(null)

  // Create task modal
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newTask, setNewTask] = useState({
    name: '',
    description: '',
    category: 'custom',
    prompt: '',
    system_prompt: '',
    tags: ''
  })
  const [creating, setCreating] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)

  useEffect(() => {
    loadTasks()
  }, [])

  useEffect(() => {
    filterTasks()
  }, [tasks, selectedCategory, searchQuery])

  const loadTasks = async () => {
    setLoading(true)
    try {
      const taskList = await agentApi.tasks.list()
      setTasks(taskList)
    } catch (error) {
      console.error('Failed to load tasks:', error)
    } finally {
      setLoading(false)
    }
  }

  const filterTasks = () => {
    let filtered = [...tasks]

    // Category filter
    if (selectedCategory !== 'all') {
      filtered = filtered.filter(t => t.category === selectedCategory)
    }

    // Search filter
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(t =>
        t.name.toLowerCase().includes(query) ||
        t.description.toLowerCase().includes(query) ||
        t.tags?.some(tag => tag.toLowerCase().includes(query))
      )
    }

    setFilteredTasks(filtered)
  }

  const handleCreateTask = async () => {
    if (!newTask.name.trim() || !newTask.prompt.trim()) return

    setCreating(true)
    try {
      await agentApi.tasks.create({
        name: newTask.name,
        description: newTask.description,
        category: newTask.category,
        prompt: newTask.prompt,
        system_prompt: newTask.system_prompt || undefined,
        tags: newTask.tags.split(',').map(t => t.trim()).filter(t => t)
      })

      // Reload tasks
      await loadTasks()
      setShowCreateModal(false)
      setNewTask({
        name: '',
        description: '',
        category: 'custom',
        prompt: '',
        system_prompt: '',
        tags: ''
      })
    } catch (error) {
      console.error('Failed to create task:', error)
    } finally {
      setCreating(false)
    }
  }

  const handleDeleteTask = async (taskId: string) => {
    try {
      await agentApi.tasks.delete(taskId)
      await loadTasks()
      setDeleteConfirm(null)
      if (selectedTask?.id === taskId) {
        setSelectedTask(null)
      }
    } catch (error) {
      console.error('Failed to delete task:', error)
    }
  }

  const handleRunTask = (task: AgentTask) => {
    // Navigate to new scan page with task pre-selected
    navigate('/scan/new', { state: { selectedTaskId: task.id } })
  }

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <BookOpen className="w-8 h-8 text-primary-500" />
            Task Library
          </h1>
          <p className="text-dark-400 mt-1">Manage and create reusable security testing tasks</p>
        </div>
        <Button onClick={() => setShowCreateModal(true)}>
          <Plus className="w-4 h-4 mr-2" />
          Create Task
        </Button>
      </div>

      {/* Filters */}
      <Card>
        <div className="flex flex-wrap gap-4">
          {/* Search */}
          <div className="flex-1 min-w-[200px]">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
              <input
                type="text"
                placeholder="Search tasks..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-dark-900 border border-dark-700 rounded-lg text-white placeholder-dark-500 focus:border-primary-500 focus:outline-none"
              />
            </div>
          </div>

          {/* Category Filter */}
          <div className="flex gap-2 flex-wrap">
            {CATEGORIES.map((cat) => (
              <Button
                key={cat.id}
                variant={selectedCategory === cat.id ? 'primary' : 'secondary'}
                size="sm"
                onClick={() => setSelectedCategory(cat.id)}
              >
                {cat.name}
              </Button>
            ))}
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Task List */}
        <div className="lg:col-span-2 space-y-3">
          {loading ? (
            <Card>
              <p className="text-dark-400 text-center py-8">Loading tasks...</p>
            </Card>
          ) : filteredTasks.length === 0 ? (
            <Card>
              <p className="text-dark-400 text-center py-8">
                {searchQuery || selectedCategory !== 'all'
                  ? 'No tasks match your filters'
                  : 'No tasks found. Create your first task!'}
              </p>
            </Card>
          ) : (
            filteredTasks.map((task) => (
              <div
                key={task.id}
                onClick={() => setSelectedTask(task)}
                className={`bg-dark-800 rounded-lg border p-4 cursor-pointer transition-all ${
                  selectedTask?.id === task.id
                    ? 'border-primary-500 bg-primary-500/5'
                    : 'border-dark-700 hover:border-dark-500'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium text-white">{task.name}</span>
                      {task.is_preset && (
                        <span className="text-xs bg-primary-500/20 text-primary-400 px-2 py-0.5 rounded">
                          Preset
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-dark-400 line-clamp-2">{task.description}</p>

                    <div className="flex items-center gap-3 mt-3">
                      <span className={`text-xs px-2 py-0.5 rounded ${
                        task.category === 'full_auto' ? 'bg-primary-500/20 text-primary-400' :
                        task.category === 'recon' ? 'bg-blue-500/20 text-blue-400' :
                        task.category === 'vulnerability' ? 'bg-orange-500/20 text-orange-400' :
                        task.category === 'reporting' ? 'bg-green-500/20 text-green-400' :
                        'bg-purple-500/20 text-purple-400'
                      }`}>
                        {task.category}
                      </span>
                      {task.estimated_tokens > 0 && (
                        <span className="text-xs text-dark-500 flex items-center gap-1">
                          <Zap className="w-3 h-3" />
                          ~{task.estimated_tokens} tokens
                        </span>
                      )}
                    </div>

                    {task.tags?.length > 0 && (
                      <div className="flex gap-1 mt-2 flex-wrap">
                        {task.tags.slice(0, 5).map((tag) => (
                          <span key={tag} className="text-xs bg-dark-700 text-dark-300 px-2 py-0.5 rounded flex items-center gap-1">
                            <Tag className="w-3 h-3" />
                            {tag}
                          </span>
                        ))}
                        {task.tags.length > 5 && (
                          <span className="text-xs text-dark-500">+{task.tags.length - 5} more</span>
                        )}
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation()
                        handleRunTask(task)
                      }}
                    >
                      <Play className="w-4 h-4" />
                    </Button>
                    {!task.is_preset && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation()
                          setDeleteConfirm(task.id)
                        }}
                      >
                        <Trash2 className="w-4 h-4 text-red-400" />
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Task Details */}
        <div>
          <Card title="Task Details">
            {selectedTask ? (
              <div className="space-y-4">
                <div>
                  <p className="text-sm text-dark-400">Name</p>
                  <p className="text-white font-medium">{selectedTask.name}</p>
                </div>

                <div>
                  <p className="text-sm text-dark-400">Description</p>
                  <p className="text-dark-300">{selectedTask.description}</p>
                </div>

                <div>
                  <p className="text-sm text-dark-400">Category</p>
                  <p className="text-white">{selectedTask.category}</p>
                </div>

                <div>
                  <p className="text-sm text-dark-400">Prompt</p>
                  <pre className="text-xs bg-dark-900 p-3 rounded-lg overflow-auto max-h-60 text-dark-300 whitespace-pre-wrap">
                    {selectedTask.prompt}
                  </pre>
                </div>

                {selectedTask.system_prompt && (
                  <div>
                    <p className="text-sm text-dark-400">System Prompt</p>
                    <pre className="text-xs bg-dark-900 p-3 rounded-lg overflow-auto max-h-40 text-dark-300 whitespace-pre-wrap">
                      {selectedTask.system_prompt}
                    </pre>
                  </div>
                )}

                {selectedTask.tools_required?.length > 0 && (
                  <div>
                    <p className="text-sm text-dark-400">Required Tools</p>
                    <div className="flex gap-1 flex-wrap mt-1">
                      {selectedTask.tools_required.map((tool) => (
                        <span key={tool} className="text-xs bg-dark-700 text-dark-300 px-2 py-1 rounded">
                          {tool}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div className="pt-4 border-t border-dark-700">
                  <Button
                    className="w-full"
                    onClick={() => handleRunTask(selectedTask)}
                  >
                    <Play className="w-4 h-4 mr-2" />
                    Run This Task
                  </Button>
                </div>
              </div>
            ) : (
              <p className="text-dark-400 text-center py-8">
                Select a task to view details
              </p>
            )}
          </Card>
        </div>
      </div>

      {/* Create Task Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-800 rounded-xl border border-dark-700 w-full max-w-2xl max-h-[90vh] overflow-auto">
            <div className="flex items-center justify-between p-4 border-b border-dark-700">
              <h3 className="text-xl font-bold text-white">Create New Task</h3>
              <Button variant="ghost" size="sm" onClick={() => setShowCreateModal(false)}>
                <X className="w-5 h-5" />
              </Button>
            </div>

            <div className="p-4 space-y-4">
              <Input
                label="Task Name"
                placeholder="My Custom Task"
                value={newTask.name}
                onChange={(e) => setNewTask({ ...newTask, name: e.target.value })}
              />

              <Input
                label="Description"
                placeholder="Brief description of what this task does"
                value={newTask.description}
                onChange={(e) => setNewTask({ ...newTask, description: e.target.value })}
              />

              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">Category</label>
                <select
                  value={newTask.category}
                  onChange={(e) => setNewTask({ ...newTask, category: e.target.value })}
                  className="w-full px-4 py-2 bg-dark-900 border border-dark-700 rounded-lg text-white focus:border-primary-500 focus:outline-none"
                >
                  <option value="custom">Custom</option>
                  <option value="recon">Reconnaissance</option>
                  <option value="vulnerability">Vulnerability</option>
                  <option value="full_auto">Full Auto</option>
                  <option value="reporting">Reporting</option>
                </select>
              </div>

              <Textarea
                label="Prompt"
                placeholder="Enter the prompt for the AI agent..."
                rows={8}
                value={newTask.prompt}
                onChange={(e) => setNewTask({ ...newTask, prompt: e.target.value })}
              />

              <Textarea
                label="System Prompt (Optional)"
                placeholder="Enter a system prompt to guide the AI's behavior..."
                rows={4}
                value={newTask.system_prompt}
                onChange={(e) => setNewTask({ ...newTask, system_prompt: e.target.value })}
              />

              <Input
                label="Tags (comma separated)"
                placeholder="pentest, api, auth, custom"
                value={newTask.tags}
                onChange={(e) => setNewTask({ ...newTask, tags: e.target.value })}
              />
            </div>

            <div className="flex justify-end gap-3 p-4 border-t border-dark-700">
              <Button variant="secondary" onClick={() => setShowCreateModal(false)}>
                Cancel
              </Button>
              <Button
                onClick={handleCreateTask}
                isLoading={creating}
                disabled={!newTask.name.trim() || !newTask.prompt.trim()}
              >
                <Save className="w-4 h-4 mr-2" />
                Create Task
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteConfirm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-dark-800 rounded-xl border border-dark-700 p-6 max-w-md">
            <h3 className="text-xl font-bold text-white mb-2">Delete Task?</h3>
            <p className="text-dark-400 mb-6">
              Are you sure you want to delete this task? This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <Button variant="secondary" onClick={() => setDeleteConfirm(null)}>
                Cancel
              </Button>
              <Button variant="danger" onClick={() => handleDeleteTask(deleteConfirm)}>
                <Trash2 className="w-4 h-4 mr-2" />
                Delete
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
