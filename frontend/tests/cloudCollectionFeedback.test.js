import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  formatCloudCollectMessage,
  formatCloudDemoFeedback,
  formatCloudN8nFeedback,
} from '../src/cloud/cloudCollectionFeedback.js'

describe('cloud collection feedback', () => {
  it('explains missing presentation allow-list', () => {
    const text = formatCloudDemoFeedback({ demo_feedback: { presentation_enabled: false } })
    assert.match(text, /PRESENTATION_TELEMETRY_EMAILS/)
  })

  it('reports demo incident created with risk', () => {
    const text = formatCloudDemoFeedback({
      demo_feedback: { presentation_enabled: true, demo_incident_created: true, trigger_risk_score: 70 },
    })
    assert.match(text, /DEMO incident created/)
    assert.match(text, /70\/100/)
  })

  it('does not claim mailbox delivery when webhook is SENT', () => {
    const note = formatCloudN8nFeedback({
      dispatch_status: 'SENT',
      sequence_number: 4,
      policy: 'cloud_demo_every_success',
      trigger_every: 1,
    })
    assert.match(note, /webhook accepted/i)
    assert.match(note, /not confirmed/i)
    assert.doesNotMatch(note, /^n8n sent for collection/)
  })

  it('combines collection, demo, and webhook lines', () => {
    const message = formatCloudCollectMessage({
      status: 'COLLECTION_OK',
      outcome: 'SUCCESS',
      records_retrieved: 0,
      records_inserted: 0,
      records_deduplicated: 0,
      demo_feedback: { presentation_enabled: true, demo_incident_created: true, trigger_risk_score: 70 },
      collection_n8n: { dispatch_status: 'SENT', sequence_number: 1, policy: 'cloud_demo_every_success', trigger_every: 1 },
    })
    assert.match(message, /retrieved 0/)
    assert.match(message, /DEMO incident created/)
    assert.match(message, /webhook accepted/)
  })
})
