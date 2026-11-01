type RuntimeEnv = {
  VITE_API_BASE_URL?: string
  VITE_DEPOSITGUARD_INSTITUTION_ID?: string
  DEV?: boolean
}

const env = (import.meta as ImportMeta & { env?: RuntimeEnv }).env ?? {}

export const API_BASE_URL = (
  env.VITE_API_BASE_URL ?? (env.DEV ? 'http://localhost:8000' : '')
).replace(/\/$/, '')

export const CONFIGURED_INSTITUTION_ID = env.VITE_DEPOSITGUARD_INSTITUTION_ID?.trim() ?? ''

export type Institution = { id: string; name: string; created_at: string }
export type FDRRecord = {
  id: string; institution_id: string; instrument_reference: string | null
  workflow_stage: string; created_at: string; updated_at: string
}
export type WorkflowConfig = {
  version: string; initial_stage: string
  stages: { key: string; label: string }[]
  transitions: { from_stage: string; to_stage: string }[]
  decision_stages?: string[]; clarification_stages?: string[]
  document_requirements: { key: string; label: string; required: boolean }[]
}
export type AuditEvent = {
  id: string; institution_id: string; fdr_record_id: string | null; event_type: string; actor_id: string; configuration_version: string | null; from_stage: string | null
  to_stage: string | null; reason: string | null; details: Record<string, unknown>; created_at: string
}
export type DocumentVersion = {
  id: string; document_id: string; configuration_version: string; version_number: number
  original_filename: string; byte_size: number; media_type: string; digest_algorithm: string
  sha256_digest: string; uploaded_by: string; uploaded_at: string
  upload_policy_version?: string | null; upload_policy_digest?: string | null
}
export type FDRDocument = {
  id: string; institution_id: string; fdr_record_id: string; category_key: string
  created_by: string; created_at: string; latest_version: DocumentVersion | null
  versions?: DocumentVersion[]; versions_error?: string
}
export type EvidenceCheck = {
  id: string; institution_id: string; fdr_record_id: string; document_version_id: string | null
  check_type: string; result_status: 'PASS' | 'FAIL' | 'INDETERMINATE'; explanation: string
  software_version: string | null; rule_version: string | null; evidence_references: string[]
  result_details: Record<string, unknown>; human_review_decision: string | null; executed_at: string
}
export type Relationship = {
  id: string; institution_id: string; source_record_id: string; target_record_id: string
  relationship_type: string; relationship_label: string; review_status: string; note: string | null
  created_by: string; created_at: string
}
export type GraphPolicy = { policy: { version: string; max_traversal_depth: number; max_nodes: number; relationship_types: { key: string; label: string; allow_cycles: boolean }[] } }
export type GraphNode = { entity_type: string; entity_id: string; institution_id: string; label: string; depth: number }
export type GraphEdge = {
  edge_id: string; source: string; source_id: string; target: string; target_id: string
  relationship_type: string; relationship_label: string; review_status: string | null; traversal_depth: number
}
export type GraphResult = { algorithm: 'BFS' | 'DFS'; start_node: GraphNode; max_depth: number; max_nodes: number; truncated: boolean; nodes: GraphNode[]; edges: GraphEdge[] }
export type Factor = { factor: string; points: number; evaluated: boolean; explanation: string; missing_inputs: string[] }
export type UrgencyScore = {
  calculation_id: string; institution_id: string; record_id: string; score: number
  priority_category_key: string; priority_category_label: string; policy_version: string
  policy_digest: string; workflow_config_version: string; calculated_at: string
  factors: Factor[]; missing_inputs: string[]
}
export type PriorityItem = UrgencyScore & { workflow_stage: string; updated_at: string; relevant_deadline: string | null }
export type PriorityQueue = { institution_id: string; policy_version: string; policy_digest: string; calculated_at: string; items: PriorityItem[] }
export type DashboardSummary = {
  institution_id: string; total_records: number; stage_counts: Record<string, number>; document_count: number
  integrity_check_counts: Record<string, number>; recent_activity: AuditEvent[]
}
export type AuthRole = 'system_admin' | 'institution_admin' | 'document_officer' | 'reviewer' | 'approver' | 'auditor'
export type AuthUser = {
  id: string; email: string; display_name: string; system_admin: boolean; active: boolean
  must_change_password: boolean; memberships: { institution_id: string; role: Exclude<AuthRole, 'system_admin'> }[]
  created_at: string
}
export type AuthSession = { user: AuthUser; csrf_token: string }
export type ManagedUser = AuthUser
export type PriorityPolicyInfo = { policy: { version: string; description: string }; policy_digest: string }
export type UploadPolicyInfo = { policy: { version: string; max_file_size_bytes: number; allowed_file_types: { file_format: string; extensions: string[]; media_type: string }[] }; policy_digest: string }

export class ApiError extends Error {
  status: number
  code: string
  constructor(message: string, status: number, code = 'api_error') {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

async function request<T>(path: string, init: RequestInit = {}, csrf = true): Promise<T> {
  let response: Response
  const headers = new Headers(init.headers)
  if (csrf && csrfToken && init.method && !['GET', 'HEAD', 'OPTIONS'].includes(init.method.toUpperCase())) {
    headers.set('X-CSRF-Token', csrfToken)
  }
  try {
    response = await fetch(`${API_BASE_URL}/api${path}`, { ...init, headers, credentials: 'include' })
  } catch {
    throw new ApiError(`Cannot reach DepositGuard API at ${API_BASE_URL}. Start the backend and check VITE_API_BASE_URL.`, 0, 'connection_error')
  }
  if (!response.ok) {
    const payload = await response.json().catch(() => undefined)
    if (response.status === 401 && !['/auth/login', '/auth/session'].includes(path)) {
      window.dispatchEvent(new Event('depositguard:unauthorized'))
    }
    throw new ApiError(
      payload?.error?.message ?? `Request failed with HTTP ${response.status}.`,
      response.status,
      payload?.error?.code ?? 'api_error',
    )
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

const json = (body: unknown): RequestInit => ({
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})
const enc = encodeURIComponent
let csrfToken = ''
export const setCsrfToken = (value: string) => { csrfToken = value }

export const api = {
  login: (email: string, password: string) => request<AuthSession>('/auth/login', json({ email, password }), false),
  registerUser: (payload: { email: string; display_name: string; password: string; role: string; institution_id?: string | null }) => request<AuthSession>('/auth/register', json(payload), false),
  session: () => request<AuthSession>('/auth/session'),
  logout: () => request<void>('/auth/logout', { method: 'POST' }),
  changePassword: (current_password: string, new_password: string) => request<void>('/auth/change-password', json({ current_password, new_password })),
  listUsers: () => request<ManagedUser[]>('/auth/users?limit=500'),
  createUser: (payload: { email: string; display_name: string; temporary_password: string; system_admin: boolean; institution_id: string | null; role: string | null }) => request<ManagedUser>('/auth/users', json(payload)),
  setUserActive: (userId: string, active: boolean) => request<ManagedUser>(`/auth/users/${enc(userId)}/active`, { ...json({ active }), method: 'PATCH' }),
  assignMembership: (userId: string, institution_id: string, role: string) => request<ManagedUser>(`/auth/users/${enc(userId)}/memberships`, { ...json({ institution_id, role }), method: 'PUT' }),
  resetUserPassword: (userId: string, temporary_password: string) => request<void>(`/auth/users/${enc(userId)}/password-reset`, json({ temporary_password })),
  priorityPolicy: () => request<PriorityPolicyInfo>('/review-priority/policy'),
  uploadPolicy: () => request<UploadPolicyInfo>('/documents/policy'),
  listInstitutions: () => request<Institution[]>('/institutions?limit=500'),
  listPublicInstitutions: () => request<Institution[]>('/public/institutions?limit=500'),
  createInstitution: (name: string, actor_id: string) => request<Institution>('/institutions', json({ name, actor_id })),
  listRecords: (institutionId: string) => request<FDRRecord[]>(`/institutions/${enc(institutionId)}/fdr-records?limit=500`),
  dashboardSummary: (institutionId: string) => request<DashboardSummary>(`/institutions/${enc(institutionId)}/dashboard-summary`),
  createRecord: (institutionId: string, instrument_reference: string | null, actor_id: string) => request<FDRRecord>(`/institutions/${enc(institutionId)}/fdr-records`, json({ instrument_reference, actor_id })),
  getRecord: (institutionId: string, recordId: string) => request<FDRRecord>(`/institutions/${enc(institutionId)}/fdr-records/${enc(recordId)}`),
  getWorkflow: () => request<{ config: WorkflowConfig }>('/workflow/configuration'),
  transition: (institutionId: string, recordId: string, target_stage: string, actor_id: string, reason: string) => request<FDRRecord>(`/institutions/${enc(institutionId)}/fdr-records/${enc(recordId)}/transitions`, json({ target_stage, actor_id, reason: reason || null })),
  getAudit: (institutionId: string, recordId: string) => request<AuditEvent[]>(`/institutions/${enc(institutionId)}/fdr-records/${enc(recordId)}/audit-events?limit=200`),
  uploadDocument: (institutionId: string, recordId: string, category_key: string, actor_id: string, file: File, document_id?: string) => {
    const body = new FormData()
    body.set('category_key', category_key)
    body.set('actor_id', actor_id)
    body.set('file', file)
    if (document_id) body.set('document_id', document_id)
    return request<FDRDocument>(`/institutions/${enc(institutionId)}/fdr-records/${enc(recordId)}/documents`, { method: 'POST', body })
  },
  listDocuments: (institutionId: string, recordId: string) => request<FDRDocument[]>(`/institutions/${enc(institutionId)}/fdr-records/${enc(recordId)}/documents`),
  listVersions: (institutionId: string, recordId: string, documentId: string) => request<DocumentVersion[]>(`/institutions/${enc(institutionId)}/fdr-records/${enc(recordId)}/documents/${enc(documentId)}/versions`),
  integrityCheck: (institutionId: string, recordId: string, documentId: string, versionId: string, actor_id: string) => request<EvidenceCheck>(`/institutions/${enc(institutionId)}/fdr-records/${enc(recordId)}/documents/${enc(documentId)}/versions/${enc(versionId)}/integrity-checks`, json({ actor_id })),
  listEvidence: (institutionId: string, recordId: string) => request<EvidenceCheck[]>(`/institutions/${enc(institutionId)}/fdr-records/${enc(recordId)}/evidence-checks?limit=200`),
  getGraphPolicy: () => request<GraphPolicy>('/graph/policy'),
  createRelationship: (institutionId: string, recordId: string, target_record_id: string, relationship_type: string, actor_id: string, note: string) => request<Relationship>(`/institutions/${enc(institutionId)}/fdr-records/${enc(recordId)}/relationships`, json({ target_record_id, relationship_type, review_status: 'unreviewed', actor_id, note: note || null })),
  listRelationships: (institutionId: string, recordId: string) => request<Relationship[]>(`/institutions/${enc(institutionId)}/fdr-records/${enc(recordId)}/relationships?limit=500`),
  graph: (institutionId: string, recordId: string, algorithm: 'BFS' | 'DFS' = 'BFS') => request<GraphResult>(`/institutions/${enc(institutionId)}/fdr-records/${enc(recordId)}/graph?algorithm=${algorithm}`),
  urgencyScore: (institutionId: string, recordId: string) => request<UrgencyScore>(`/institutions/${enc(institutionId)}/fdr-records/${enc(recordId)}/urgency-score`),
  priorityQueue: (institutionId: string, signal?: AbortSignal) => request<PriorityQueue>(`/institutions/${enc(institutionId)}/review-priority-queue?limit=500`, { signal }),
}
